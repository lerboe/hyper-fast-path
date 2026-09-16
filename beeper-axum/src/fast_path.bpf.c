#include "beeper.h"
#include "xbpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// The fast path of the example server. It parses the requests arriving on the
// server's sockets and answers the ones it has a pre-rendered response for
// right here, without ever waking up user space.

// The most dummy sockets, and so the most connections the fast path runs on at
// once, see `dummy_map`. User space sizes the maps to the pool it sets up.
#define MAX_DUMMIES 16384

// Tracks how far an upgraded connection's HTTP/2 handshake has progressed, so
// that a connection present in the map is known to speak HTTP/2.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} upgraded_conns SEC(".maps");
u32 num_upgraded_conns = 0;

// The sockets the server accepted, i.e. the ones `skb_verdict` runs on.
//
// What a client sends arrives as an sk_buff, which cannot be grown into a
// response of any size. `skb_verdict` therefore redirects it to the egress of
// the connection's dummy socket (see `dummy_map`), which has the psock backlog
// send it and so runs it through `msg_verdict`. From there a request is either
// answered, by rewriting it into the response and redirecting it to the egress
// of the client's socket, or handed to user space by redirecting it to the
// socket's ingress.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} sock_map SEC(".maps");

// The dummy sockets, i.e. the ones `msg_verdict` runs on. Each is one end of a
// loopback connection user space set up and never reads from or writes to.
//
// Every connection that takes the fast path is lent a dummy of its own, so all
// that is ever sent on it is what that client sent. This is what lets
// `bpf_msg_apply_bytes` reach past the end of a message: the next bytes sent on
// the dummy are guaranteed to continue the same stream. The server's writes on
// the client's socket never pass through the program at all.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, MAX_DUMMIES);
    __type(key, u32);
    __type(value, int);
} dummy_map SEC(".maps");

// The dummies no connection is holding. Filled by user space, which also puts a
// dummy back once it has been reset, see `released_dummies`.
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, MAX_DUMMIES);
    __type(value, u32);
} free_dummies SEC(".maps");

// The dummies whose connections closed. A dummy carries state over from the
// connection it was lent to, both in its psock and in the HTTP/2 parser's
// dynamic table, neither of which the program can reset. User space does, and
// then returns the dummy to `free_dummies`.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64);
} released_dummies SEC(".maps");

// The dummy lent to a client connection.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DUMMIES);
    __type(key, struct ip4_conn);
    __type(value, u32);
} conn_dummy SEC(".maps");

// Which dummy a message was sent on, by the dummy's address. Set up by user
// space along with the dummies themselves.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DUMMIES);
    __type(key, struct ip4_conn);
    __type(value, u32);
} dummy_idx SEC(".maps");

// The client connection a dummy is lent to.
struct dummy_owner {
    struct ip4_conn conn;
    u8 active;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_DUMMIES);
    __type(key, u32);
    __type(value, struct dummy_owner);
} dummy_owners SEC(".maps");

// The address of the server, set by user space before the program is loaded.
volatile const u32 ip4;
volatile const u32 port;

// Fast path routing table: a fixed-size, userspace-populated table (backed by
// the program's .bss section) holding pre-rendered HTTP responses. Populated by
// userspace before the program is attached.
#define MAX_ROUTES 16
#define MAX_ROUTE_PATH 64

// The most bytes the fast path adds to or reads from a message in one go.
//
// Both halves of serving a response are bounded by it. `bpf_msg_push_data`
// backs every call with a single contiguous allocation taken from an atomic
// context, which fails for all but the smallest orders, and the verifier
// refuses any packet offset past `MAX_PACKET_OFF` (64K), which is as far into a
// message as it can be addressed. A chunk is exactly one scatterlist element,
// so pulling one back in never has to linearize anything either.
#define CHUNK 32768

// The most chunks a response is built from. A message holds `MAX_MSG_FRAGS`
// (17) scatterlist elements, a couple of which the request itself takes up.
#define MAX_CHUNKS 14

#define MAX_ROUTE_BODY (MAX_CHUNKS * CHUNK)

// The most stream ids a response carries, one per frame. An HTTP/2 body is
// split across as many DATA frames as its peer's SETTINGS_MAX_FRAME_SIZE
// allows, and every one of their headers names the stream it belongs to.
#define MAX_SID_OFFS 32

// The address the arena holding the pre-rendered responses is mapped at, and
// how far it reaches. Naming the address rather than letting mmap pick one is
// what lets an offset mean the same thing here and in user space.
//
// The reach is the most the routing table could ever need. Nothing is spent on
// it up front: a page of an arena is only allocated once it is written to, and
// user space shrinks the map to the routes it actually configured.
#define ARENA_BASE (1ull << 44)
#define ARENA_PAGES (MAX_ROUTES * 2 * MAX_ROUTE_BODY / 4096)

#define __arena __attribute__((address_space(1)))

// The matches the parsers are configured with, in the order in which user
// space captures them.
#define H1_PREFACE_MID 0
#define H1_PATH_MID 1
#define H1_CONTENT_LENGTH_MID 2
#define H2_PATH_MID 0
#define H2_CONTENT_LENGTH_MID 1

#define H2_SETTINGS_FRAME 0x04
#define H2_WINDOW_UPDATE_FRAME 0x08
#define H2_ACK_FLAG 0x01

// The SETTINGS parameter that names the flow control window a stream starts
// out with, see RFC 7540 section 6.5.2.
#define H2_SETTINGS_INITIAL_WINDOW_SIZE 0x04

// how far along an upgraded connection is. only once the handshake completed
// can the fast path answer on it without preempting the server's SETTINGS.
#define H2_UPGRADED 1
#define H2_HANDSHAKED 2

// The number of entries of the HPACK static table. A dynamic table entry is
// addressed by the index that follows them, see `BEEPER_H2_GET_DT_ENTRY`.
#define STATIC_TABLE_SIZE 61

// The frame type the fast path prepends its dynamic table changes to a
// forwarded message under.
//
// 0xFB is not assigned by RFC 7540, so an HTTP/2 implementation that does not
// know about it is required to discard it rather than choke on it. The user
// space wrapper (see `listener.rs`) picks it out of the stream before the
// server's own codec ever sees it.
#define DT_SYNC_FRAME_TYPE 0xFB

// The most entries a single sync frame carries. A table larger than this
// cannot be replayed, so the fast path stops answering on that connection
// instead of letting the two tables drift apart silently.
#define MAX_SYNC_ENTRIES 8

// The most bytes a sync frame's body can take up. An entry needs at most two
// length bytes plus a name and a value, both of which the parser truncates to
// `BEEPER_H2_FIELD_MAXLEN`.
#define MAX_SYNC_BODY (MAX_SYNC_ENTRIES * (2 + 2 * BEEPER_H2_FIELD_MAXLEN))

// The size of the buffer the body is built up in, with room to spare so that
// an offset clamped to `MAX_SYNC_BODY` is always well inside it.
#define MAX_SYNC_BUF 4096

// The longest name or value a sync frame spells out. HPACK would encode a
// longer string with a multi byte length, which the encoder below does not
// bother to emit.
#define MAX_SYNC_FIELD 126

// Whether the fast path has answered a request on a connection since user
// space last saw one, i.e. whether the two dynamic tables may have drifted
// apart. Set when a request is served, cleared once the difference has been
// handed over.
//
// Only a flag is kept, not a count of what changed: a request the fast path
// answers can evict entries as well as add them, and once user space is
// holding entries the client has already dropped there is no set of additions
// that puts the two back in step. The sync frame therefore replays the whole
// table rather than a delta.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, u8);
} dt_dirty SEC(".maps");

// Scratch space for the sync frame that is being built, along with the entry
// that is being read out of the dynamic table into it. Both are far too large
// to live on the stack the verifier allows.
struct dt_sync_buf {
    u8 data[MAX_SYNC_BUF];
    u32 len;
    struct header_field hf;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dt_sync_buf);
} dt_sync_scratch SEC(".maps");

// The frame type the fast path reports the bytes it answered with to user
// space under.
//
// 0xFB's neighbour, and unassigned for the same reason. It is picked out of the
// stream by the same wrapper, see `listener.rs`.
#define FC_SYNC_FRAME_TYPE 0xFA

// The connection level flow control window an HTTP/2 connection opens with,
// see RFC 7540 section 6.9.2. SETTINGS cannot change it, only WINDOW_UPDATE
// can, which is what makes it something the fast path can follow on its own.
#define H2_INITIAL_WINDOW 65535

// The largest window either side may open, see RFC 7540 section 6.9.1.
#define H2_MAX_WINDOW 0x7FFFFFFF

// The most SETTINGS parameters the fast path reads out of one frame, and how
// many bytes each of them takes up.
#define MAX_SETTINGS 16
#define H2_SETTING_LEN 6

// How much of a connection's flow control the fast path may spend.
//
// Only what the client announces is tracked here, as that is all the fast path
// gets to see: it runs on the client's socket, so every SETTINGS and
// WINDOW_UPDATE the client sends passes through it, while the server's own
// responses go out on a socket it never observes. Those responses spend the
// connection window too, which is what `unreported` is for -- user space is
// handed the fast path's share and takes it out of its own accounting, see
// `prepend_fc_sync`.
//
// The reverse does not hold: what the server sends never reaches `conn_window`,
// so it runs ahead of the window the client really has open by exactly the
// bytes the server has sent since the last WINDOW_UPDATE. Closing that would
// take a report in the other direction, which is a channel the fast path does
// not have.
struct h2_flow {
    // what is left of the connection level window. it can go negative if the
    // client shrinks a window it had already opened.
    s32 conn_window;

    // the window a stream opens with, i.e. the client's
    // SETTINGS_INITIAL_WINDOW_SIZE. every stream the fast path answers on is
    // fresh, so this is the whole of its stream window.
    u32 stream_window;

    // bytes the fast path has sent that user space has not been told about
    // yet, and so still believes it may spend itself
    u32 unreported;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, struct h2_flow);
} flow_ctl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, ARENA_PAGES);
    __ulong(map_extra, ARENA_BASE);
} arena SEC(".maps");

// The program's handle on the arena. Referring to it is what ties the two
// together, which is how the verifier knows where an arena address points, and
// it is the only pointer into the arena the program is handed.
//
// It is a single byte: what user space writes into the arena has no shape the
// program needs to know, as every response is found through the offset its
// route carries, and declaring the whole run here would have libbpf write out
// -- and so allocate -- all of it at load time.
u8 __arena route_data[1];

// The arena address `off` bytes into the responses.
//
// libbpf places a program's arena globals at the end of the arena, which is not
// where user space lays the responses out, so `route_data` is only used to find
// the arena's start again: an arena pointer is its offset into the arena, and
// reading one back as an integer is what hands that offset over.
static __always_inline const u8 __arena *arena_at(u32 off) {
    u32 anchor = (u32)(unsigned long)route_data;

    return route_data - anchor + off;
}

// A pre-rendered response, as a pair of offsets into the arena. The bodies
// themselves live in the arena, so a route costs a handful of bytes here no
// matter how large the file it answers with is.
struct route {
    // the response rendered as HTTP/1.1
    u32 body_off;
    u32 body_len;

    // the same response rendered as an h2 HEADERS frame followed by as many
    // DATA frames as the body needs, along with the offsets of the stream ids
    // in their frame headers
    u32 h2_body_off;
    u32 h2_body_len;
    u32 h2_sid_offs[MAX_SID_OFFS];
    u32 h2_sid_count;

    // how much of the h2 rendering is flow controlled, i.e. the DATA payloads
    // without the frame headers around them
    u32 h2_data_len;
};

struct route routes[MAX_ROUTES];

// The request path, zero padded to a fixed size so that it can be hashed.
struct route_key {
    u8 path[MAX_ROUTE_PATH];
};

// Maps a request path to its index in `routes`. Populated by userspace once the
// program is loaded, as a hash map only exists from then on. A route is
// reachable under several paths, the plain text one and the huffman encoded one
// h2 puts on the wire, hence the two entries per route.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2 * MAX_ROUTES);
    __type(key, struct route_key);
    __type(value, u8);
} route_idx SEC(".maps");

// The functions beeper replaces with an HTTP/1.1 parser.
BEEPER_MATCHED(matched_h1)
BEEPER_EXTRACT_MATCH(extract_h1_match)
BEEPER_H1_PARSE_MSG(parse_h1)

// The functions beeper replaces with an HTTP/2 parser.
BEEPER_EXTRACT_MATCH(extract_h2_match)
BEEPER_H2_PARSE_MSG(parse_h2)
BEEPER_H2_GET_DT_ENTRY(get_dt_entry)

// Appends `len` bytes of `src` to `buf`. Returns 0 on success, -1 if the
// buffer is full.
static __always_inline int sync_put(struct dt_sync_buf *buf, const u8 *src, u32 len) {
    u32 off = buf->len;
    if (len > MAX_SYNC_FIELD || off + len > MAX_SYNC_BODY) return -1;

    u32 i;
    bpf_for(i, 0, len) {
        u32 j = i;
        bpf_clamp_uminmax(j, 0, MAX_SYNC_FIELD - 1);

        // clamping rather than masking, as clang folds a mask away again once
        // it thinks the bound check above already established the range
        u32 o = off + j;
        bpf_clamp_uminmax(o, 0, MAX_SYNC_BODY - 1);

        buf->data[o] = src[j];
    }

    buf->len = off + len;

    return 0;
}

// Appends the single byte `c` to `buf`. Returns 0 on success, -1 if the buffer
// is full.
static __always_inline int sync_put_byte(struct dt_sync_buf *buf, u8 c) {
    u32 off = buf->len;
    if (off + 1 > MAX_SYNC_BODY) return -1;
    bpf_clamp_uminmax(off, 0, MAX_SYNC_BODY - 1);

    buf->data[off] = c;
    buf->len = off + 1;

    return 0;
}

// Renders the whole of `conn`'s dynamic table into `buf` as an HPACK block,
// `n` entries, oldest first, so that a decoder replaying the block ends up
// holding exactly what the fast path last saw the client holding.
//
// This is a resync rather than a delta: a request the fast path answered may
// have evicted entries as well as added them, and only a decoder that starts
// from an empty table ends up agreeing with the client again. Emptying it is
// the reader's job, see `Decoder::prime` in the patched `vendor/h2` -- the size
// the table has to be restored to afterwards is the one the reader announced,
// which is not something the fast path knows.
//
// Every entry is written as a literal header field with incremental indexing
// and a new name (RFC 7541 section 6.2.1), which is the representation that
// makes a decoder add it to its dynamic table. Names and values are copied
// straight out of the mirrored table, in whichever form the client sent them.
//
// Returns 0 if the whole table was written, -1 if an entry could not be read or
// does not fit, in which case `buf` is left incomplete and must be discarded.
static __always_inline int render_dt_sync(struct dt_sync_buf *buf, const struct ip4_conn *conn, u32 n) {
    u32 i;
    bpf_for(i, 0, n) {
        // the entries to replay are the `n` most recent ones, i.e. HPACK
        // indices 1 through `n`, and the oldest of those has to go first
        u32 idx = STATIC_TABLE_SIZE + (n - i);
        if (get_dt_entry(conn, idx, &buf->hf) < 0) {
            bpf_warn("dt sync: entry %u is gone", idx);
            return -1;
        }

        u32 key_len = buf->hf.key_len;
        u32 val_len = buf->hf.val_len;
        if (key_len == 0 || key_len > MAX_SYNC_FIELD || val_len > MAX_SYNC_FIELD) {
            bpf_warn("dt sync: entry %u does not fit", idx);
            return -1;
        }

        // the entry is copied over in whatever form it arrived in, so the H bit
        // has to say which one that was rather than assume Huffman
        u8 key_huff = buf->hf.key_huff ? 0x80 : 0;
        u8 val_huff = buf->hf.val_huff ? 0x80 : 0;

        if (sync_put_byte(buf, 0x40) < 0) return -1;
        if (sync_put_byte(buf, key_huff | key_len) < 0) return -1;
        if (sync_put(buf, buf->hf.key, key_len) < 0) return -1;
        if (sync_put_byte(buf, val_huff | val_len) < 0) return -1;
        if (sync_put(buf, buf->hf.val, val_len) < 0) return -1;
    }

    return 0;
}

// Prepends the dynamic table of `msg`'s connection to `msg`, as a frame of
// type `DT_SYNC_FRAME_TYPE`, so that user space can bring its own table back in
// line with it.
//
// The frame goes in front of the message rather than replacing it: the message
// still has to reach the server, it just has to be preceded by the table
// updates that make its HPACK indices resolve to the right fields.
//
// Returns the number of bytes prepended, or -1 if the frame could not be
// built, in which case `msg` is left untouched.
static __always_inline int prepend_dt_sync(struct sk_msg_md *msg, const struct ip4_conn *conn, u32 n) {
    u32 zero = 0;
    struct dt_sync_buf *buf = bpf_map_lookup_elem(&dt_sync_scratch, &zero);
    if (!buf) return -1;

    // the frame header is written once the body's length is known, so the body
    // is built up behind it
    buf->len = 0;
    if (render_dt_sync(buf, conn, n) < 0) return -1;

    // an empty table is worth handing over too: it says the client dropped
    // everything it had, and a reader that is still holding those entries has
    // to be brought down to nothing along with it
    u32 body_len = buf->len;
    if (body_len > MAX_SYNC_BODY) return -1;
    bpf_clamp_uminmax(body_len, 0, MAX_SYNC_BODY);

    u32 frame_len = 9 + body_len;
    u32 orig_size = msg->size;

    if (bpf_msg_push_data(msg, 0, frame_len, 0) < 0) return -1;
    if (bpf_msg_pull_data(msg, 0, frame_len, 0) < 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    // the bound has to be established on the very pointer that is written
    // through, and with a constant offset, or the verifier does not carry it
    // over to `data` itself
    if (data + 9 > data_end) return -1;

    data[0] = (body_len >> 16) & 0xFF;
    data[1] = (body_len >> 8) & 0xFF;
    data[2] = body_len & 0xFF;
    data[3] = DT_SYNC_FRAME_TYPE;
    data[4] = 0;
    // the sync frame describes the connection, not a stream
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;
    data[8] = 0;

    u32 i;
    bpf_for(i, 0, body_len) {
        u32 j = i;
        bpf_clamp_uminmax(j, 0, MAX_SYNC_BODY - 1);

        // same again: the check has to sit on `p`, not on a pointer `p` is
        // later derived from
        u8 *p = data + 9 + j;
        if (p + 1 > data_end) return -1;

        *p = buf->data[j];
    }

    bpf_debug("dt sync: prepended %u entries (%uB) to a %uB msg", n, frame_len, orig_size);

    return frame_len;
}

// Follows the SETTINGS or WINDOW_UPDATE frame `msg` carries into the flow
// control the fast path spends from.
//
// The payload is read straight off the message, so this invalidates whatever
// the parser captured out of it. Neither frame carries a request, so there is
// nothing left to extract from one anyway.
static __always_inline void track_flow(struct sk_msg_md *msg, const struct ip4_conn *conn, const struct h2_frame *frame) {
    struct h2_flow *fc = bpf_map_lookup_elem(&flow_ctl, conn);
    if (!fc) return;

    u32 want = (frame->type == H2_WINDOW_UPDATE_FRAME) ? 13 : 9 + MAX_SETTINGS * H2_SETTING_LEN;
    if (want > msg->size) want = msg->size;
    if (bpf_msg_pull_data(msg, 0, want, 0) < 0) return;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;
    if (data + 9 > data_end) return;

    u32 payload_len = ((u32)data[0] << 16) | ((u32)data[1] << 8) | data[2];

    if (frame->type == H2_WINDOW_UPDATE_FRAME) {
        // a window update for a stream the fast path answered on is worth
        // nothing: that stream is closed and its window can never be spent
        // again. only the connection level one carries over.
        if (frame->sid != 0 || payload_len != 4) return;
        if (data + 13 > data_end) return;

        // the reserved bit is not part of the increment
        u32 inc = (((u32)data[9] << 24) | ((u32)data[10] << 16) |
                   ((u32)data[11] << 8) | data[12]) & H2_MAX_WINDOW;

        s64 window = (s64)fc->conn_window + inc;
        fc->conn_window = window > H2_MAX_WINDOW ? H2_MAX_WINDOW : (s32)window;

        bpf_trace("flow: connection window is %d", fc->conn_window);

        return;
    }

    if (frame->flags & H2_ACK_FLAG) return;

    u32 n = payload_len / H2_SETTING_LEN;
    if (n > MAX_SETTINGS) n = MAX_SETTINGS;

    u32 i;
    bpf_for(i, 0, n) {
        u32 j = i;
        bpf_clamp_uminmax(j, 0, MAX_SETTINGS - 1);

        u8 *p = data + 9 + j * H2_SETTING_LEN;
        if (p + H2_SETTING_LEN > data_end) return;

        if ((((u16)p[0] << 8) | p[1]) != H2_SETTINGS_INITIAL_WINDOW_SIZE) continue;

        u32 val = ((u32)p[2] << 24) | ((u32)p[3] << 16) | ((u32)p[4] << 8) | p[5];
        // a window the client cannot legally announce is left to user space to
        // reject rather than acted on here
        if (val > H2_MAX_WINDOW) return;

        fc->stream_window = val;

        bpf_trace("flow: stream window is %u", fc->stream_window);
    }
}

// Prepends the bytes the fast path has answered with on this connection to
// `msg`, as a frame of type `FC_SYNC_FRAME_TYPE`, so that user space can take
// them out of the send window its own codec believes it still has.
//
// Returns the number of bytes prepended, or -1 if the frame could not be
// built, in which case `msg` is left untouched.
static __always_inline int prepend_fc_sync(struct sk_msg_md *msg, u32 sent) {
    if (bpf_msg_push_data(msg, 0, 13, 0) < 0) return -1;
    if (bpf_msg_pull_data(msg, 0, 13, 0) < 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;
    if (data + 13 > data_end) return -1;

    data[0] = 0;
    data[1] = 0;
    data[2] = 4;
    data[3] = FC_SYNC_FRAME_TYPE;
    data[4] = 0;
    // the bytes were spent on the connection as a whole, whichever streams
    // they went out on
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;
    data[8] = 0;
    data[9] = (sent >> 24) & 0xFF;
    data[10] = (sent >> 16) & 0xFF;
    data[11] = (sent >> 8) & 0xFF;
    data[12] = sent & 0xFF;

    bpf_debug("flow: reporting %uB served out of band", sent);

    return 13;
}

// Writes `sid` into the frame header at `off`, where h2 keeps the stream id.
//
// The four bytes are pulled in on their own rather than reached through the
// window the response was copied in: a response runs well past what a message
// can be addressed through, and a frame header that sits near a chunk boundary
// would otherwise be split across two of those windows.
static __always_inline int write_sid(struct sk_msg_md *msg, u32 off, u32 sid) {
    if (off + 4 > MAX_ROUTE_BODY) return -1;

    if (bpf_msg_pull_data(msg, off, off + 4, 0) < 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;
    if (data + 4 > data_end) return -1;

    data[0] = (sid >> 24) & 0xFF;
    data[1] = (sid >> 16) & 0xFF;
    data[2] = (sid >> 8) & 0xFF;
    data[3] = sid & 0xFF;

    return 0;
}

// How many bytes one turn of the copy loop moves. A byte at a time spends an
// iterator step and a bounds check on every single one of them; a block spends
// them once and moves eight bytes at a time underneath.
#define COPY_BLOCK 256

// Copies `len` bytes of `src` into the message window that `bpf_msg_pull_data`
// last made addressable. Returns 0 on success, < 0 if the window is short.
static __always_inline int copy_chunk(struct sk_msg_md *msg, const u8 __arena *src, u32 len) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    // a helper cannot write into a message, so the copy is spelled out. `len`
    // bounds it, the packet check is what the verifier goes by. the read side
    // needs no bound of its own, as an arena access that lands outside the
    // arena is caught rather than allowed to wander.
    u32 done = 0;

    u32 b;
    bpf_for(b, 0, CHUNK / COPY_BLOCK) {
        u32 off = b * COPY_BLOCK;
        if (off + COPY_BLOCK > len) break;

        // the check has to name the pointer the stores are reached through for
        // the verifier to carry its range over to them, so the block's start is
        // taken once and everything below hangs off it
        u8 *dst = data + off;
        if (dst + COPY_BLOCK > data_end) return -1;

        // widening the read needs a pointer of the wider type, and clang drops
        // the arena address space on its way through the cast, leaving a load
        // the verifier reads as one off a plain scalar. the barrier is what
        // stops it folding the two together, and so what keeps the cast.
        const u8 __arena *p = src + off;
        asm volatile("" : "+r"(p));

        // neither side is aligned to eight: responses sit back to back in the
        // arena, and a window starts wherever the message put it. the verifier
        // only holds unaligned access against a target that pays for it, which
        // x86 and arm64 do not.
        const u64 __arena *words = (const u64 __arena *)p;

#pragma unroll
        for (u32 w = 0; w < COPY_BLOCK / 8; w++) {
            *(u64 *)(dst + w * 8) = words[w];
        }

        done = off + COPY_BLOCK;
    }

    // whatever the last whole block left behind, which is shorter than one
    u32 k;
    bpf_for(k, 0, COPY_BLOCK) {
        u32 off = done + k;
        if (off >= len) break;
        if (data + off + 1 > data_end) return -1;

        data[off] = src[off];
    }

    return 0;
}

// Overwrites the request taking up the first `req_len` bytes of `msg` with
// `r`'s pre-rendered response and redirects it to the egress of the client's
// socket, bypassing userspace entirely. Whatever follows the request is run through the program
// again. `sid` is the h2 stream to answer on, or 0 to serve the HTTP/1.1
// rendering.
//
// Returns 0 on success, -1 if the response could not be served and `msg` is
// untouched, -2 if `msg` was left half rewritten and has to be dropped.
static __always_inline int serve_route(struct sk_msg_md *msg, struct ip4_conn *ikey, struct route *r, u32 sid, u32 req_len) {
    bool is_h2 = (sid != 0);
    u32 body_len = is_h2 ? r->h2_body_len : r->body_len;
    if (body_len == 0 || body_len > MAX_ROUTE_BODY) return -1;

    // an h2 response goes out in one piece or not at all: the fast path has
    // nowhere to park what does not fit and no way of being woken when the
    // client reopens its window. a response the client has no room for is
    // therefore left to user space, which can wait it out.
    struct h2_flow *fc = NULL;
    if (is_h2) {
        fc = bpf_map_lookup_elem(&flow_ctl, ikey);
        if (!fc) return -1;

        u32 data_len = r->h2_data_len;
        if (fc->conn_window < 0 || (u32)fc->conn_window < data_len || fc->stream_window < data_len) {
            bpf_debug("Not serving request, %uB do not fit the client's window (connection %d, stream %u)",
                      data_len, fc->conn_window, fc->stream_window);

            return -1;
        }
    }

    u32 orig_size = msg->size;
    if (req_len == 0 || req_len > orig_size) return -1;

    // the request has to end up holding exactly the response. growing it goes
    // a chunk at a time, as a single push of the whole difference asks the
    // allocator for one contiguous block of it.
    if (body_len > req_len) {
        u32 target = orig_size + (body_len - req_len);

        u32 i;
        bpf_for(i, 0, MAX_CHUNKS) {
            // read back on every turn rather than counted up, as a counter
            // carried across turns keeps the verifier from ever converging
            u32 size = msg->size;
            if (size >= target) break;

            u32 grow = target - size;
            if (grow > CHUNK) grow = CHUNK;

            // the response grows at its end, which is where the request ended
            u32 end = req_len + (size - orig_size);

            if (bpf_msg_push_data(msg, end, grow, 0) < 0) return i == 0 ? -1 : -2;
        }

        if (msg->size != target) return -2;
    } else if (body_len < req_len) {
        if (bpf_msg_pop_data(msg, body_len, req_len - body_len, 0) < 0) return -1;
    }

    // the response is copied in one window at a time, each of which is pulled
    // in on its own. a window is what the push above made one scatterlist
    // element, so pulling it is free, and `msg->data` is rebased to its start,
    // which keeps every offset the verifier sees well under `MAX_PACKET_OFF`.
    u32 c;
    bpf_for(c, 0, MAX_CHUNKS) {
        u32 off = c * CHUNK;
        if (off >= body_len) break;

        u32 len = body_len - off;
        if (len > CHUNK) len = CHUNK;

        if (bpf_msg_pull_data(msg, off, off + len, 0) < 0) return -2;

        u32 body_off = is_h2 ? r->h2_body_off : r->body_off;

        if (copy_chunk(msg, arena_at(body_off + off), len) < 0) return -2;
    }

    // the rendered frames carry a zeroed stream id, the one of the request
    // this responds to is only known here
    if (is_h2) {
        u32 i;
        bpf_for(i, 0, MAX_SID_OFFS) {
            if (i >= r->h2_sid_count) break;

            u32 j = i;
            bpf_clamp_uminmax(j, 0, MAX_SID_OFFS - 1);

            if (write_sid(msg, r->h2_sid_offs[j], sid) < 0) return -2;
        }
    }

    if (bpf_msg_redirect_hash(msg, &sock_map, ikey, 0) != SK_PASS) return -2;

    bpf_msg_apply_bytes(msg, body_len);

    // the client's window is spent now, and so is the server's share of it,
    // which is what user space has to be told about
    if (fc) {
        fc->conn_window -= r->h2_data_len;
        fc->unreported += r->h2_data_len;
    }

    return 0;
}

// Looks up the captured request path in `route_idx` and, on a match, serves
// the pre-rendered response directly from the fast path. Returns 0 if a route
// was served (the caller should return SK_PASS immediately without further
// processing `msg`), < 0 otherwise, see `serve_route`.
static __always_inline int try_serve_route(struct sk_msg_md *msg, struct ip4_conn *ikey, struct hdr_str *path, u32 sid, u32 req_len) {
    if (path->len == 0 || path->len > MAX_ROUTE_PATH) return -1;

    u32 len = path->len;
    bpf_clamp_uminmax(len, 1, MAX_ROUTE_PATH);

    struct route_key key = { 0 };
    if (bpf_probe_read_kernel(key.path, len, path->ptr) < 0) return -1;

    u8 *idx = bpf_map_lookup_elem(&route_idx, &key);
    if (!idx) {
        bpf_warn("No route found for request path");
        return -1;
    };

    u32 i = *idx;
    bpf_clamp_uminmax(i, 0, MAX_ROUTES - 1);

    return serve_route(msg, ikey, &routes[i], sid, req_len);
}

// Hands the next `len` bytes the client sent to user space, which may reach
// past the end of `msg`, see `dummy_map`.
static __always_inline int to_user_space(struct sk_msg_md *msg, struct ip4_conn *conn, u32 len) {
    bpf_msg_apply_bytes(msg, len);

    return bpf_msg_redirect_hash(msg, &sock_map, conn, BPF_F_INGRESS);
}

// Returns the value of the captured `Content-Length` header, or -1 if it is
// empty or not a number. It is what tells the fast path how far the body of a
// request reaches, as the parser itself stops at the end of the header block.
static __always_inline int parse_content_length(const struct hdr_str *content_length) {
    char digits[16] = { 0 };
    u32 n = content_length->len;
    if (n > 0) {
        bpf_clamp_uminmax(n, 1, sizeof(digits) - 1);

        if (bpf_probe_read_kernel(digits, n, content_length->ptr) == 0) {
            unsigned long len = 0;
            if (bpf_strtoul(digits, n, 0, &len) >= 0 && len > 0) {
                return len;
            }
        }
    }

    return -1;
}

// Parses the request the message carries and serves it from the fast path if it
// asks for one of the pre-rendered routes. Anything else is passed on to the
// user space server.
SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // the dummy the message was sent on. the HTTP/2 parser keys its state by
    // the address of the socket it runs on, which is this one.
    struct ip4_conn dkey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    u32 *dummy = bpf_map_lookup_elem(&dummy_idx, &dkey);
    if (!dummy) return SK_DROP;

    struct dummy_owner *owner = bpf_map_lookup_elem(&dummy_owners, dummy);
    // what is left over from a connection that closed has nowhere to go
    if (!owner || !owner->active) return SK_DROP;

    // socket identifier of the client connection
    struct ip4_conn ikey = owner->conn;

    bpf_debug("Processing %dB msg from [%pI4:%u->%pI4:%u]", msg->size, &ikey.remote.ip4, ikey.remote.port, &ikey.local.ip4, ikey.local.port);

    int *conn_state = bpf_map_lookup_elem(&upgraded_conns, &ikey);
    bool is_h2 = (conn_state != NULL);
    // the map entry may be reallocated by the update below, so keep a copy
    int h2_state = is_h2 ? *conn_state : 0;
    int msg_len = -1;
    struct parse_res pres = { 0 };
    struct hdr_str path = { 0 };
    int path_res = -1;
    u32 sid = 0;

    // whether the two dynamic tables may have drifted apart, and what it takes
    // to replay the mirrored one if they have
    bool dt_stale = false;
    u32 dt_count = 0;

    if (is_h2) {
        struct h2_frame frame = { 0 };
        msg_len = parse_h2(msg, &pres, &frame);
        if (msg_len >= 0) {
            sid = frame.sid;

            u8 *dirty = bpf_map_lookup_elem(&dt_dirty, &ikey);
            dt_stale = (dirty != NULL && *dirty != 0);

            // the table as it stands before this message, which is the state
            // user space has to reach before decoding it. the entries this
            // message itself adds are none of the sync frame's business, user
            // space adds those when it decodes it.
            dt_count = frame.dt_count_before;

            // a client only acks SETTINGS once it has received the server's, so
            // this is the point from which a response cannot preempt the
            // handshake anymore
            if (frame.type == H2_SETTINGS_FRAME && (frame.flags & H2_ACK_FLAG) && h2_state < H2_HANDSHAKED) {
                bpf_trace("HTTP/2 handshake complete");

                h2_state = H2_HANDSHAKED;
                bpf_map_update_elem(&upgraded_conns, &ikey, &h2_state, BPF_ANY);
            }

            if (frame.type == H2_SETTINGS_FRAME || frame.type == H2_WINDOW_UPDATE_FRAME) {
                track_flow(msg, &ikey, &frame);
            }
            else {
                struct hdr_str content_length = { 0 };
                if (extract_h2_match(msg, &pres, H2_CONTENT_LENGTH_MID, &content_length) == 0) {
                    bpf_trace("content length: %s", content_length.ptr);

                    int res = parse_content_length(&content_length);
                    if (res > 0) msg_len += res;
                }

                path_res = extract_h2_match(msg, &pres, H2_PATH_MID, &path);
            }
        }
    }
    else {
        msg_len = parse_h1(msg, &pres);
        if (msg_len > 0) {
            if (matched_h1(msg, &pres, H1_PREFACE_MID)) {
                bpf_trace("Upgrading connection to HTTP/2");

                int val = H2_UPGRADED;
                bpf_map_update_elem(&upgraded_conns, &ikey, &val, BPF_ANY);
                num_upgraded_conns++;

                struct h2_flow flow = {
                    .conn_window = H2_INITIAL_WINDOW,
                    .stream_window = H2_INITIAL_WINDOW,
                };
                bpf_map_update_elem(&flow_ctl, &ikey, &flow, BPF_ANY);

                // the H2 preface is 24 bytes long
                return to_user_space(msg, &ikey, 24);
            }

            struct hdr_str content_length = { 0 };
            if (extract_h1_match(msg, &pres, H1_CONTENT_LENGTH_MID, &content_length) == 0) {
                bpf_trace("content length: %s", content_length.ptr);

                int res = parse_content_length(&content_length);
                if (res > 0) msg_len += res;
            }

            path_res = extract_h1_match(msg, &pres, H1_PATH_MID, &path);
        }
    }

    // answering before the h2 handshake completed would preempt the server's
    // SETTINGS, so such requests are left to userspace
    bool can_serve = (path_res == 0) && (!is_h2 || h2_state >= H2_HANDSHAKED);
    if (path_res == 0 && !can_serve) {
        bpf_debug("Not serving request, HTTP/2 handshake is still in flight");
    }

    // a table too large to replay cannot be handed over, so answering here
    // would strand user space for good. the request goes to it instead, which
    // is always safe: decoding it is what keeps the two tables in step.
    if (can_serve && dt_count > MAX_SYNC_ENTRIES) {
        bpf_warn("Not serving request, the dynamic table holds %u entries", dt_count);
        can_serve = false;
    }

    if (can_serve && msg_len > 0) {
        int served = try_serve_route(msg, &ikey, &path, sid, msg_len);
        if (served < -1) {
            bpf_error("Failed to serve request, dropping it");
            return SK_DROP;
        }

        if (served == 0) {
            bpf_debug("Served request");

            // user space knows nothing of this request, and the header block
            // just decoded may well have changed the dynamic table, so the
            // next message it does get has to carry the table with it
            if (is_h2) {
                u8 dirty = 1;
                bpf_map_update_elem(&dt_dirty, &ikey, &dirty, BPF_ANY);
            }

            // the redirect to the client's socket was set up while serving
            return SK_PASS;
        }
    }

    // the message is going to user space, so this is the moment to hand the
    // dynamic table over. once it is in front of the message, user space
    // rebuilds the table from it and then decodes the message against it,
    // ending up exactly where the fast path's mirror is.
    if (is_h2 && msg_len >= 0 && dt_stale) {
        int synced = prepend_dt_sync(msg, &dkey, dt_count);
        if (synced < 0) {
            bpf_error("Failed to sync dynamic table, dropping connection");

            // letting the message through now would have user space decode it
            // against a table that no longer matches the client's, which
            // desyncs HPACK for good. cutting the connection is the lesser evil.
            return SK_DROP;
        }

        msg_len += synced;

        u8 dirty = 0;
        bpf_map_update_elem(&dt_dirty, &ikey, &dirty, BPF_ANY);
    }

    // and the moment to hand over what the fast path spent of the connection's
    // window. it goes in front of the dynamic table update, so that user space
    // has taken the bytes out of its own accounting before it looks at
    // anything that might have it send more.
    if (is_h2 && msg_len >= 0) {
        struct h2_flow *fc = bpf_map_lookup_elem(&flow_ctl, &ikey);
        if (fc && fc->unreported > 0) {
            int reported = prepend_fc_sync(msg, fc->unreported);
            if (reported < 0) {
                // nothing is lost by leaving it for the next message: the fast
                // path has already taken the bytes out of its own window, so
                // it will not overrun the client while user space catches up
                bpf_warn("Failed to report %uB served out of band", fc->unreported);
            }
            else {
                msg_len += reported;
                fc->unreported = 0;
            }
        }
    }

    // a message that could not be parsed continues in a later sk_buff, where
    // there is no telling where the next one starts. the rest of the connection
    // is left to user space.
    if (msg_len <= 0) {
        bpf_debug("Failed to parse msg, handing the connection to user space");

        return to_user_space(msg, &ikey, 0xFFFFFFFF);
    }

    return to_user_space(msg, &ikey, msg_len);
}

// Sends what the client sent through `msg_verdict`, see `sock_map`.
SEC("sk_skb/stream_verdict")
int skb_verdict(struct __sk_buff *skb) {
    struct ip4_conn ikey = {
        .local = {
            .ip4 = skb->local_ip4,
            .port = skb->local_port
        },
        .remote = {
            .ip4 = skb->remote_ip4,
            .port = bpf_ntohl(skb->remote_port)
        }
    };

    // a socket is only added once it holds a dummy, and only loses it once it
    // is closed
    u32 *dummy = bpf_map_lookup_elem(&conn_dummy, &ikey);
    if (!dummy) return SK_DROP;

    // the end of the stream arrives as an empty sk_buff. the backlog takes
    // sending nothing for a broken pipe, which would leave the dummy unusable
    // for every connection after this one, so it goes to user space directly.
    if (skb->len == 0) return SK_PASS;

    // the backlog sends the linear part and every fragment of an sk_buff with a
    // sendmsg of their own. `msg_verdict` copes with either, but one message is
    // cheaper to run it on than several.
    if (bpf_skb_pull_data(skb, skb->len) < 0) {
        bpf_debug("Failed to linearize %uB skb", skb->len);
    }

    return bpf_sk_redirect_map(skb, &dummy_map, *dummy, 0);
}

// Lends a dummy to a connection the server accepted and adds it to `sock_map`.
// A connection that finds no dummy left is served by user space alone.
static __always_inline void add_conn(struct bpf_sock_ops *ops, struct ip4_conn *key) {
    u32 dummy;
    if (bpf_map_pop_elem(&free_dummies, &dummy) < 0) {
        bpf_warn("No dummy left for [%pI4:%u->%pI4:%u], leaving it to user space", &key->remote.ip4, key->remote.port, &key->local.ip4, key->local.port);
        return;
    }

    struct dummy_owner owner = { .conn = *key, .active = 1 };
    if (bpf_map_update_elem(&dummy_owners, &dummy, &owner, BPF_ANY) < 0) goto release;
    if (bpf_map_update_elem(&conn_dummy, key, &dummy, BPF_ANY) < 0) goto release;

    // the dummy has to be given back once the connection closes
    if (bpf_sock_ops_cb_flags_set(ops, BPF_SOCK_OPS_STATE_CB_FLAG) < 0) goto release;

    if (bpf_sock_hash_update(ops, &sock_map, key, BPF_ANY) < 0) {
        bpf_error("Failed to add socket [%pI4:%u->%pI4:%u]", &key->local.ip4, key->local.port, &key->remote.ip4, key->remote.port);
        goto release;
    }

    bpf_debug("Added socket [%pI4:%u->%pI4:%u] with dummy %u", &key->local.ip4, key->local.port, &key->remote.ip4, key->remote.port, dummy);

    return;

release:
    // the dummy was never used, so it can go straight back
    bpf_sock_ops_cb_flags_set(ops, 0);
    bpf_map_delete_elem(&conn_dummy, key);
    owner.active = 0;
    bpf_map_update_elem(&dummy_owners, &dummy, &owner, BPF_ANY);
    bpf_map_push_elem(&free_dummies, &dummy, BPF_ANY);
}

// Takes the dummy back from a connection that closed, along with the state the
// fast path kept for it.
static __always_inline void remove_conn(struct ip4_conn *key) {
    u32 *found = bpf_map_lookup_elem(&conn_dummy, key);
    if (!found) return;

    u32 dummy = *found;
    bpf_map_delete_elem(&conn_dummy, key);

    // whatever the dummy still has queued is dropped from here on
    struct dummy_owner owner = { .conn = *key, .active = 0 };
    bpf_map_update_elem(&dummy_owners, &dummy, &owner, BPF_ANY);

    bpf_map_delete_elem(&upgraded_conns, key);
    bpf_map_delete_elem(&flow_ctl, key);
    bpf_map_delete_elem(&dt_dirty, key);

    if (bpf_ringbuf_output(&released_dummies, &dummy, sizeof(dummy), 0) < 0) {
        bpf_error("Failed to release dummy %u, it is lost to the pool", dummy);
        return;
    }

    bpf_debug("Released dummy %u of [%pI4:%u->%pI4:%u]", dummy, &key->local.ip4, key->local.port, &key->remote.ip4, key->remote.port);
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && ops->op != BPF_SOCK_OPS_STATE_CB) {
        return SK_PASS;
    }

    struct ip4_conn skey = {
        .local = {
            .ip4 = ops->local_ip4,
            .port = ops->local_port
        },
        .remote = {
            .ip4 = ops->remote_ip4,
            .port = bpf_ntohl(ops->remote_port)
        }
    };

    if (ops->op == BPF_SOCK_OPS_STATE_CB) {
        if (ops->args[1] == BPF_TCP_CLOSE) remove_conn(&skey);

        return SK_PASS;
    }

    // a server bound to the unspecified address accepts on all of them
    if ((ip4 == 0 || skey.local.ip4 == ip4) && skey.local.port == port) {
        add_conn(ops, &skey);
    }

    return SK_PASS;
}
