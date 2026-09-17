//! The pool of dummy sockets the fast path runs `msg_verdict` on, see
//! `dummy_map` in `fast_path.bpf.c`.
//!
//! A dummy is lent to a connection by the sockops program and handed back over
//! a ring buffer once the connection closes. It still carries the connection's
//! state at that point, so it is reset here before it goes back into the pool.

use anyhow::{Context, Result, bail};
use std::{
    cell::RefCell,
    collections::VecDeque,
    ffi::OsStr,
    io, mem,
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, BorrowedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tracing::{debug, error};
use xbpf::libbpf::{
    ErrorKind, MapCore, MapFlags, MapHandle, RingBufferBuilder, libbpf_sys,
    query::{LinkInfoIter, LinkTypeInfo, ProgInfoIter, ProgInfoQueryOptions},
};

/// How long a released dummy is left alone before it is reset. Its backlog may
/// still be working off what the connection sent last, and a psock that is in
/// use when the dummy is taken out of the map outlives the removal.
const QUARANTINE: Duration = Duration::from_millis(100);

/// How often the recycler checks whether it should stop.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The name the HTTP/2 parser's `dynamic_table_info` map goes by. The kernel
/// cuts map names to 15 bytes.
const DYNAMIC_TABLE_INFO: &str = "dynamic_table_i";

/// The maps the pool is managed through.
pub(crate) struct DummyMaps {
    pub dummy_map: MapHandle,
    pub dummy_idx: MapHandle,
    pub free_dummies: MapHandle,
    pub released_dummies: MapHandle,
    pub dynamic_table_info: MapHandle,
}

/// One end of a loopback connection, the other end of which is only kept open.
struct Dummy {
    sender: TcpStream,
    _receiver: TcpStream,
    key: [u8; 16],
}

/// The dummies along with the thread that recycles them. Dropping the pool
/// stops the thread and closes the dummies.
pub(crate) struct DummyPool {
    stop: Arc<AtomicBool>,
    recycler: Option<JoinHandle<()>>,
}

impl DummyPool {
    /// Opens `n` dummies, registers them with the fast path and starts recycling
    /// them.
    pub fn new(n: usize, maps: DummyMaps) -> Result<Self> {
        // both ends of every dummy take up a file descriptor
        raise_fd_limit(2 * n as u64 + 1024)?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let mut dummies = Vec::with_capacity(n);
        for idx in 0..n as u32 {
            let sender = TcpStream::connect(addr)?;
            let (receiver, _) = listener.accept()?;
            let key = conn_key(sender.local_addr()?, sender.peer_addr()?)?;

            let dummy = Dummy {
                sender,
                _receiver: receiver,
                key,
            };

            maps.dummy_map
                .update(&idx.to_ne_bytes(), &fd_bytes(&dummy), MapFlags::ANY)
                .with_context(|| format!("failed to add dummy {idx}"))?;
            maps.dummy_idx
                .update(&key, &idx.to_ne_bytes(), MapFlags::ANY)?;
            maps.free_dummies
                .update(&[], &idx.to_ne_bytes(), MapFlags::ANY)?;

            dummies.push(dummy);
        }

        debug!("Opened {n} dummy sockets");

        let stop = Arc::new(AtomicBool::new(false));
        let recycler = thread::Builder::new()
            .name("beeper-dummies".into())
            .spawn({
                let stop = stop.clone();
                move || {
                    if let Err(e) = recycle(&maps, &dummies, &stop) {
                        error!("Stopped recycling dummy sockets: {e:?}");
                    }
                }
            })?;

        Ok(Self {
            stop,
            recycler: Some(recycler),
        })
    }
}

impl Drop for DummyPool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);

        if let Some(recycler) = self.recycler.take() {
            let _ = recycler.join();
        }
    }
}

/// Resets the dummies the fast path releases and returns them to the pool,
/// until `stop` is set.
fn recycle(maps: &DummyMaps, dummies: &[Dummy], stop: &AtomicBool) -> Result<()> {
    let released = RefCell::new(VecDeque::new());

    let mut builder = RingBufferBuilder::new();
    builder.add(&maps.released_dummies, |data: &[u8]| {
        let Ok(idx) = data.try_into().map(u32::from_ne_bytes) else {
            return 0;
        };

        released.borrow_mut().push_back((idx, Instant::now()));
        0
    })?;
    let ringbuf = builder.build()?;

    while !stop.load(Ordering::Relaxed) {
        ringbuf.poll(POLL_INTERVAL)?;

        let mut released = released.borrow_mut();
        while let Some(&(idx, at)) = released.front() {
            if at.elapsed() < QUARANTINE {
                break;
            }
            released.pop_front();

            if let Err(e) = reset(maps, dummies, idx) {
                error!("Failed to reset dummy {idx}, it is lost to the pool: {e:?}");
            }
        }
    }

    Ok(())
}

/// Clears what the connection a dummy was lent to left behind and puts the
/// dummy back into the pool.
fn reset(maps: &DummyMaps, dummies: &[Dummy], idx: u32) -> Result<()> {
    let Some(dummy) = dummies.get(idx as usize) else {
        bail!("there is no dummy {idx}");
    };

    // taking the dummy out of the map drops its psock, and with it an
    // unfinished `bpf_msg_apply_bytes` or cork, or a send the backlog gave up
    // on. adding it again sets up a fresh one.
    let key = idx.to_ne_bytes();
    maps.dummy_map.delete(&key)?;

    // a send the backlog gave up on also leaves an error on the socket, which
    // fails every send after it until it is read
    if let Some(e) = dummy.sender.take_error()? {
        debug!("Cleared error on dummy {idx}: {e}");
    }

    maps.dummy_map
        .update(&key, &fd_bytes(dummy), MapFlags::ANY)?;

    // the parser starts a connection it has no entry for with an empty table,
    // and whatever entries the last one left are overwritten as it adds its own
    if let Err(e) = maps.dynamic_table_info.delete(&dummy.key) {
        if e.kind() != ErrorKind::NotFound {
            return Err(e.into());
        }
    }

    maps.free_dummies.update(&[], &key, MapFlags::ANY)?;

    debug!("Recycled dummy {idx}");

    Ok(())
}

fn fd_bytes(dummy: &Dummy) -> [u8; 4] {
    dummy.sender.as_raw_fd().to_ne_bytes()
}

/// Returns the key the fast path's maps know the connection between `local`
/// and `remote` by, as `struct ip4_conn` lays it out.
fn conn_key(local: SocketAddr, remote: SocketAddr) -> Result<[u8; 16]> {
    let (SocketAddr::V4(local), SocketAddr::V4(remote)) = (local, remote) else {
        bail!("dummy sockets have to be IPv4");
    };

    let mut key = [0; 16];
    key[0..4].copy_from_slice(&local.ip().octets());
    key[4..8].copy_from_slice(&(local.port() as u32).to_ne_bytes());
    key[8..12].copy_from_slice(&remote.ip().octets());
    key[12..16].copy_from_slice(&(remote.port() as u32).to_ne_bytes());

    Ok(key)
}

/// Raises the soft limit on open file descriptors to the hard one if it is
/// below `needed`.
fn raise_fd_limit(needed: u64) -> Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error().into());
    }

    if limit.rlim_cur >= needed {
        return Ok(());
    }

    if limit.rlim_max < needed {
        bail!(
            "the dummy sockets need {needed} file descriptors, the hard limit is {}",
            limit.rlim_max
        );
    }

    limit.rlim_cur = limit.rlim_max;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error().into());
    }

    debug!("Raised the open file limit to {}", limit.rlim_cur);

    Ok(())
}

/// Finds the map the HTTP/2 parser attached to `target` keeps the state of its
/// dynamic tables in.
///
/// The parser does not hand the map out for anything but lookups, so it is
/// found through the parser itself: among the extension programs linked to
/// `target`, the one using a map of that name.
pub(crate) fn find_dynamic_table_info(target: BorrowedFd<'_>) -> Result<MapHandle> {
    let target_id = prog_info(target)?.id;

    let parsers: Vec<u32> = LinkInfoIter::default()
        .filter_map(|link| match link.info {
            LinkTypeInfo::Tracing(tracing) if tracing.target_obj_id == target_id => {
                Some(link.prog_id)
            }
            _ => None,
        })
        .collect();

    let opts = ProgInfoQueryOptions::default().include_map_ids(true);
    for prog in ProgInfoIter::with_query_opts(opts) {
        if !parsers.contains(&prog.id) {
            continue;
        }

        for id in prog.map_ids {
            let map = MapHandle::from_map_id(id)?;
            if map.name() == OsStr::new(DYNAMIC_TABLE_INFO) {
                return Ok(map);
            }
        }
    }

    bail!("the HTTP/2 parser's `{DYNAMIC_TABLE_INFO}` map was not found")
}

fn prog_info(fd: BorrowedFd<'_>) -> Result<libbpf_sys::bpf_prog_info> {
    let mut info: libbpf_sys::bpf_prog_info = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&info) as u32;

    let ret = unsafe { libbpf_sys::bpf_prog_get_info_by_fd(fd.as_raw_fd(), &mut info, &mut len) };
    if ret != 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(info)
}
