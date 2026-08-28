#![deny(unsafe_code)]

//! The daemon's one UDP socket, demultiplexed by connection id rather than by
//! address, so a client that changed networks is followed rather than lost.

use crate::attachment::Framing;
use crate::log::log;
use crate::mailbox::{ActorEvent, TrySendError};
use crate::registry::{DaemonState, SessionHandle, registry};
use crate::sink::{AttachmentSink, Coding, FrameSet, FrameWriter};
use crate::state::load_ticket;
use crate::{AttachKind, AttachmentId, FRAME_LENGTH_PREFIX, NEXT_ATTACHMENT};
use braid_dgram::packet::{HEADER_BYTES, TAG_BYTES};
use braid_dgram::{
    BASE_DATAGRAM, ConnectionId, Endpoint, Fragmentation, MAX_DATAGRAM, Received, RootSecret,
    SendError, Stats,
};
use braid_proto::wire::{PACK_TAG, pack, unpack};
use braid_proto::{
    ClientMessage, DatagramOffer, MAX_CLIENT_FRAME, MIN_DATAGRAM_FRAME, RejectReason,
    ServerMessage, Version, VersionRange,
};
use std::collections::HashMap;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
use std::thread;
use std::time::{Duration, Instant};

/// [`BASE_DATAGRAM`] is the MTU search's floor, so this bounds every budget.
const _: () = assert!(MIN_DATAGRAM_FRAME <= frame_budget(BASE_DATAGRAM - HEADER_BYTES - TAG_BYTES));

const OFFER_LIFETIME: Duration = Duration::from_secs(30);

/// The longest the transmit thread sleeps when nothing names a deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// A floor rather than zero: a connection that keeps naming *now* spins a core.
const POLL_FLOOR: Duration = Duration::from_millis(1);

/// How many reads that failed in a row end the datagram path: one thread reads
/// for every session, and Windows surfaces an ICMP port-unreachable as a reset.
const RECEIVE_ATTEMPTS: u32 = 16;

const RECEIVE_BACKOFF: Duration = Duration::from_millis(100);

/// Bytes the kernel holds for the one socket every session arrives on. Best
/// effort: the transport is correct with the default buffer and merely loses more.
const RECEIVE_BUFFER: usize = 4 * 1024 * 1024;

/// How many of the widest datagram the search can reach one thread may hand
/// over before the socket blocks it. A tick flushes a few per live connection,
/// so this is a ceiling rather than a working set.
const SEND_BURST: usize = 64;

/// Bytes the kernel holds for datagrams handed over and not yet on the wire.
/// The socket blocks, so a burst past this stalls whichever thread called
/// `send_to`: the session actor writing a repaint, or the one thread that
/// receives for every session. Charged as it is used, so the ceiling is free.
const SEND_BUFFER: usize = SEND_BURST * MAX_DATAGRAM;

/// Unauthenticated datagrams one source may cost this daemon, and the refill rate.
const ADMIT_BURST: u32 = 8;
const ADMIT_REFILL: Duration = Duration::from_millis(250);

/// The same for the daemon as a whole. This is the bound and the per-source
/// bucket only fairness: an unverified source address is a key an attacker picks.
const ADMIT_GLOBAL_BURST: u32 = 128;
const ADMIT_GLOBAL_REFILL: Duration = Duration::from_millis(25);

/// How many sources the limiter remembers. Eviction is by least recent use and
/// an evicted source returns with a full bucket: never refuse a client unseen.
const ADMIT_SOURCES: usize = 64;

/// How many more times a terminal message is said after the first.
const FAREWELL_REPEATS: u8 = 3;

/// How long between copies of a terminal message: three in a row would all
/// arrive at the same momentarily-full receive buffer.
const FAREWELL_SPACING: Duration = Duration::from_millis(250);

/// How long a connection is kept alive for a message that will not go: repeats
/// count down only on a sealed copy, so a shut window would hold it for ever.
const FAREWELL_WINDOW: Duration = Duration::from_secs(2);

/// A frame's four-byte length prefix never travels here; [`pack`]'s tag does.
const fn frame_budget(payload_limit: usize) -> usize {
    payload_limit + FRAME_LENGTH_PREFIX - PACK_TAG
}

/// The payload one datagram carries, given the frame budget cut from it.
pub(crate) const fn payload_limit(budget: usize) -> usize {
    (budget + PACK_TAG).saturating_sub(FRAME_LENGTH_PREFIX)
}

const fn datagram_width(budget: usize) -> usize {
    payload_limit(budget) + HEADER_BYTES + TAG_BYTES
}

/// What one datagram of an attachment's path currently carries. Atomic rather than
/// locked: the MTU search moves it at run time and the actor asks per repaint.
#[derive(Clone, Debug)]
pub(crate) struct PayloadLimit(Arc<AtomicUsize>);

impl PayloadLimit {
    pub(crate) fn fixed(frame_budget: usize) -> Self {
        Self(Arc::new(AtomicUsize::new(frame_budget)))
    }

    /// Bytes one frame to this client may occupy, length prefix included.
    pub(crate) fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    /// Floored at [`MIN_DATAGRAM_FRAME`], so a caller deriving a header budget by
    /// subtraction cannot reach zero.
    pub(crate) fn publish(&self, payload_limit: usize) {
        self.0.store(
            frame_budget(payload_limit).max(MIN_DATAGRAM_FRAME),
            Ordering::Relaxed,
        );
    }
}

struct Pending {
    secret: RootSecret,
    minted: Instant,
}

/// One connection's endpoint, and everything sealing a datagram touches: its own
/// mutex, so a busy sender never takes the lock the whole daemon demuxes behind.
struct Wire {
    endpoint: Endpoint,
    /// The last thing this attachment will be told, packed and held so a repeat
    /// is a fresh seal rather than a second compression. Nothing repairs these.
    farewell: Option<Vec<u8>>,
    /// Set when the connection leaves the map, which is how its sink finds out.
    retired: bool,
    /// What the session actor sizes its messages against.
    limit: PayloadLimit,
    /// So a transition is reported once rather than once per datagram.
    reported: Reported,
}

/// The last thing the log was told about one path.
#[derive(Default)]
struct Reported {
    carried: usize,
    collapsed: bool,
}

impl Wire {
    /// Republish what the path carries, after anything that could have moved it.
    fn publish(&mut self) {
        let carried = self.endpoint.payload_limit();
        let stats = self.endpoint.stats();
        if carried < self.reported.carried {
            log!(
                "datagram path narrowed from {} to {carried} bytes: {}",
                self.reported.carried,
                transport(&stats)
            );
        }
        self.reported.carried = carried;
        // Two datagrams is where recovery starts from.
        let collapsed = stats.cwnd <= 2 * stats.plpmtu;
        if collapsed && !self.reported.collapsed {
            log!("datagram window collapsed: {}", transport(&stats));
        }
        self.reported.collapsed = collapsed;
        self.limit.publish(carried);
    }
}

/// What the transport is doing, in one line: the only reader of [`Endpoint::stats`].
fn transport(stats: &Stats) -> String {
    let srtt = stats
        .srtt
        .map_or_else(|| "-".to_owned(), |srtt| format!("{}ms", srtt.as_millis()));
    format!(
        "cwnd {} in flight {} srtt {srtt} rttvar {}ms mtu {} lost {} spurious {}",
        stats.cwnd,
        stats.bytes_in_flight,
        stats.rttvar.as_millis(),
        stats.plpmtu,
        stats.lost,
        stats.spurious
    )
}

struct Live {
    wire: Arc<Mutex<Wire>>,
    /// Shared rather than owned: [`SessionHandle`] clones over a `MailboxSender`,
    /// whose clone and drop each take the mutex the actor drains behind, and the
    /// receive thread lifts this out of the map once per arriving datagram.
    handle: Arc<SessionHandle>,
    id: AttachmentId,
    /// Kept beside the map rather than inside the [`Wire`] so the receive thread
    /// can size an arriving datagram before taking the lock that verifies its tag.
    peer: SocketAddr,
    /// Shared with the wire that publishes it, for the same reason.
    limit: PayloadLimit,
    /// Negotiated in the `Resume` that opened this; every frame is read at it.
    version: Version,
}

/// A connection kept alive only to repeat its last message: a repeat has to be
/// sealed under a fresh packet number, since the same datagram twice is a replay.
struct Parting {
    wire: Arc<Mutex<Wire>>,
    /// Counted down only by a copy that was actually sealed.
    left: u8,
    due: Instant,
    expires: Instant,
    /// As [`Live`]: an arriving datagram is sized against these before the lock.
    peer: SocketAddr,
    limit: PayloadLimit,
}

/// Every connection this daemon has, by the id its datagrams carry. An `RwLock`
/// because routing only reads; lock order is this map first, a [`Wire`] second.
#[derive(Default)]
struct Connections {
    pending: HashMap<ConnectionId, Pending>,
    live: HashMap<ConnectionId, Live>,
    parting: HashMap<ConnectionId, Parting>,
}

/// Where one datagram belongs, decided in a single lock acquisition.
enum Route {
    Live(Attached),
    /// Carries no session, so nothing it sends is delivered — but the
    /// acknowledgement reopening its farewell's window arrives on this route.
    Parting(Departing),
    /// Carries nothing: [`DatagramListener::admit`] takes the secret out under
    /// the write lock, so an offer is spent once.
    Pending,
    Unknown,
}

/// The live connection a datagram belongs to, lifted out of the map.
struct Attached {
    wire: Arc<Mutex<Wire>>,
    handle: Arc<SessionHandle>,
    id: AttachmentId,
    peer: SocketAddr,
    /// The widest datagram this path carries, read once while the map was held.
    width: usize,
    version: Version,
}

/// The retiring connection a datagram belongs to, lifted out of the map.
struct Departing {
    wire: Arc<Mutex<Wire>>,
    peer: SocketAddr,
    /// The widest datagram this path carries, read once while the map was held.
    width: usize,
}

/// One datagram's connection, sender and arrival time. The clock is taken once
/// per datagram: the round-trip estimate is built out of that subtraction.
#[derive(Clone, Copy)]
struct Arrival {
    cid: ConnectionId,
    from: SocketAddr,
    at: Instant,
}

/// What one datagram turned out to be worth to the session above it.
enum Delivery {
    Command(ClientMessage),
    /// The peer closed, or said something this side cannot restate.
    Retire,
    /// A challenge, a keep-alive, or a datagram that was never ours.
    Ignore,
}

/// The receive loop's buffers, reused so a warm loop never allocates.
#[derive(Default)]
struct Scratch {
    payload: Vec<u8>,
    /// Answers sealed while a connection's lock was held, sent once it is not.
    outbound: Outbound,
}

struct Bucket {
    tokens: u32,
    /// Advanced by whole refill intervals so rounding does not lose the remainder.
    refilled: Instant,
}

impl Bucket {
    const fn full(burst: u32, now: Instant) -> Self {
        Self {
            tokens: burst,
            refilled: now,
        }
    }

    fn refill(&mut self, now: Instant, burst: u32, interval: Duration) {
        let earned = now.saturating_duration_since(self.refilled).as_nanos() / interval.as_nanos();
        if earned == 0 {
            return;
        }
        if let Ok(earned) = u32::try_from(earned)
            && earned < burst
        {
            self.tokens = (self.tokens + earned).min(burst);
            self.refilled += interval * earned;
        } else {
            // Long enough that `interval * earned` would overflow anyway.
            self.tokens = burst;
            self.refilled = now;
        }
    }

    fn spend(&mut self) -> bool {
        let Some(left) = self.tokens.checked_sub(1) else {
            return false;
        };
        self.tokens = left;
        true
    }
}

/// Datagrams from one source that has not authenticated.
struct Source {
    ip: IpAddr,
    bucket: Bucket,
    used: Instant,
}

/// Two token buckets for unauthenticated datagrams: per source for fairness,
/// daemon-wide for capacity. Consulted after the demux, never for a live connection.
#[derive(Default)]
struct Limiter {
    sources: Vec<Source>,
    /// Made on the first datagram: a bucket cannot be full at an unnamed instant.
    global: Option<Bucket>,
}

impl Limiter {
    fn slot(&mut self, ip: IpAddr, now: Instant) -> Option<usize> {
        if let Some(at) = self.sources.iter().position(|source| source.ip == ip) {
            return Some(at);
        }
        if self.sources.len() >= ADMIT_SOURCES {
            let stale = self
                .sources
                .iter()
                .enumerate()
                .min_by_key(|(_, source)| source.used)
                .map(|(at, _)| at)?;
            self.sources.swap_remove(stale);
        }
        self.sources.push(Source {
            ip,
            bucket: Bucket::full(ADMIT_BURST, now),
            used: now,
        });
        Some(self.sources.len() - 1)
    }

    fn admits(&mut self, ip: IpAddr, now: Instant) -> bool {
        let Some(source) = self.slot(ip, now).and_then(|at| self.sources.get_mut(at)) else {
            return false;
        };
        source.used = now;
        source.bucket.refill(now, ADMIT_BURST, ADMIT_REFILL);
        if !source.bucket.spend() {
            return false;
        }
        // Its own allowance first, so an exhausted source cannot drain the daemon's.
        let global = self
            .global
            .get_or_insert_with(|| Bucket::full(ADMIT_GLOBAL_BURST, now));
        global.refill(now, ADMIT_GLOBAL_BURST, ADMIT_GLOBAL_REFILL);
        global.spend()
    }
}

/// When the transmit thread must next be awake. Every path that creates a sooner
/// deadline calls [`Clock::advance`] rather than waiting for the tick to land.
#[derive(Default)]
struct Clock {
    next: Mutex<Option<Instant>>,
    wake: Condvar,
}

impl Clock {
    /// Sleep until `deadline`, or until something names an earlier one.
    fn sleep_until(&self, deadline: Instant) {
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        *next = Some(deadline);
        loop {
            let Some(target) = *next else { return };
            let Some(left) = target.checked_duration_since(Instant::now()) else {
                return;
            };
            let (guard, _) = self
                .wake
                .wait_timeout(next, left)
                .unwrap_or_else(PoisonError::into_inner);
            next = guard;
        }
    }

    /// Bring the next wake forward, if `deadline` is sooner than it.
    fn advance(&self, deadline: Instant) {
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        if next.is_none_or(|target| deadline < target) {
            *next = Some(deadline);
            self.wake.notify_one();
        }
    }
}

/// Clears `receiving` however the thread that serves offers leaves, unwinding
/// included: an offer for a socket nobody reads costs a client its probe budget.
struct Serving<'a> {
    listener: &'a DatagramListener,
    thread: &'static str,
}

impl<'a> Serving<'a> {
    fn new(listener: &'a DatagramListener, thread: &'static str) -> Self {
        Self { listener, thread }
    }
}

impl Drop for Serving<'_> {
    fn drop(&mut self) {
        self.listener.receiving.store(false, Ordering::Relaxed);
        log!("datagram {} thread stopped; no further offers", self.thread);
    }
}

pub(crate) struct DatagramListener {
    socket: UdpSocket,
    port: u16,
    connections: RwLock<Connections>,
    clock: Clock,
    /// Whether anything still reads this socket; [`Serving`] clears it on a panic.
    receiving: AtomicBool,
    /// What a probe on this socket is worth, decided once when it was bound.
    fragmentation: Fragmentation,
}

/// Either family left fragmenting is enough: one socket serves both.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn fragmenting() -> Fragmentation {
    log!(
        "this kernel would not stop fragmenting datagrams: every session will stay at \
         {BASE_DATAGRAM} bytes rather than settle above it on a path that only carries the \
         probe in pieces"
    );
    Fragmentation::Permitted
}

/// Make the MTU search's answers mean something, by refusing to fragment: a
/// fragmented probe answers "yes" for a path that carries no such datagram whole.
#[cfg(target_os = "linux")]
fn refuse_fragmentation(socket: &UdpSocket) -> Fragmentation {
    use rustix::net::sockopt::{Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};
    // Both families while dual-stack: a v4-mapped peer leaves through the v4 output
    // path, and `IPV6_MTU_DISCOVER` is `ENOPROTOOPT` on a socket that fell back.
    let dual_stack = socket.local_addr().is_ok_and(|local| local.is_ipv6());
    let v6_refused = dual_stack
        && rustix::net::sockopt::set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::DO).is_err();
    let v4_refused =
        rustix::net::sockopt::set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::DO).is_err();
    if !v6_refused && !v4_refused {
        return Fragmentation::Refused;
    }
    fragmenting()
}

/// The same on Darwin, where rustix exposes neither option. An oversize
/// `sendto` then fails with `EMSGSIZE`, which [`path_refused`] already reads as
/// a path that narrowed rather than as a socket that broke.
#[cfg(target_vendor = "apple")]
#[allow(
    unsafe_code,
    reason = "IP_DONTFRAG and IPV6_DONTFRAG have no safe binding"
)]
fn refuse_fragmentation(socket: &UdpSocket) -> Fragmentation {
    use std::os::fd::AsRawFd;

    /// Darwin's `netinet6/in6.h`; `libc` declares the v4 option only.
    const IPV6_DONTFRAG: libc::c_int = 62;
    /// Both options take one `c_int`, which is the length `setsockopt` is told.
    const _: () = assert!(size_of::<libc::c_int>() == 4);

    let refuse = |level: libc::c_int, option: libc::c_int| {
        let on: libc::c_int = 1;
        // SAFETY: `socket` owns the descriptor for the whole call, and `on` is
        // live, correctly typed, and named at exactly its own length.
        let set = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                std::ptr::from_ref(&on).cast(),
                4,
            )
        };
        set == 0
    };
    // Both families while dual-stack, for the reason the Linux path gives.
    let dual_stack = socket.local_addr().is_ok_and(|local| local.is_ipv6());
    let v6_refused = dual_stack && !refuse(libc::IPPROTO_IPV6, IPV6_DONTFRAG);
    let v4_refused = !refuse(libc::IPPROTO_IP, libc::IP_DONTFRAG);
    if !v6_refused && !v4_refused {
        return Fragmentation::Refused;
    }
    fragmenting()
}

/// rustix exposes neither `IP_DONTFRAG` nor `IPV6_DONTFRAG`.
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn refuse_fragmentation(_: &UdpSocket) -> Fragmentation {
    log!(
        "datagram sockets here cannot be told to stop fragmenting, so every session stays at \
         {BASE_DATAGRAM} bytes rather than settle above it on a path that only carries the \
         probe in pieces"
    );
    Fragmentation::Permitted
}

/// Ask for both buffers and say so when the kernel would not give them: Linux
/// clamps to `net.core.rmem_max` and `wmem_max`, 208 KiB on a stock kernel, and
/// a `setsockopt` that returned `Ok` is not the memory being there.
fn size_buffers(socket: &UdpSocket) {
    use rustix::net::sockopt::{
        set_socket_recv_buffer_size, set_socket_send_buffer_size, socket_recv_buffer_size,
        socket_send_buffer_size,
    };
    let _ = set_socket_recv_buffer_size(socket, RECEIVE_BUFFER);
    let _ = set_socket_send_buffer_size(socket, SEND_BUFFER);
    // Linux reads back twice what it granted, the double being its own
    // bookkeeping, so falling short of what was asked is short by over half.
    if let Ok(granted) = socket_recv_buffer_size(socket)
        && granted < RECEIVE_BUFFER
    {
        log!(
            "this socket holds {granted} bytes of arriving datagrams rather than the \
             {RECEIVE_BUFFER} asked for (net.core.rmem_max): a burst past that is dropped \
             before any session sees it"
        );
    }
    if let Ok(granted) = socket_send_buffer_size(socket)
        && granted < SEND_BUFFER
    {
        log!(
            "this socket holds {granted} bytes of departing datagrams rather than the \
             {SEND_BUFFER} asked for (net.core.wmem_max): a burst past that parks the thread \
             that sent it"
        );
    }
}

impl DatagramListener {
    /// Take a socket for the whole daemon, or decide there is no second path.
    pub(crate) fn bind() -> Option<Arc<Self>> {
        // Dual-stack, so an offer can name a v4-mapped address without a second port.
        let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
            .or_else(|_| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)));
        let socket = match socket {
            Ok(socket) => socket,
            Err(error) => {
                log!("no datagram transport: {error}");
                return None;
            }
        };
        size_buffers(&socket);
        let fragmentation = refuse_fragmentation(&socket);
        let port = match socket.local_addr() {
            Ok(local) => local.port(),
            Err(error) => {
                log!("no datagram transport: {error}");
                return None;
            }
        };
        log!("daemon: datagram transport on port {port}");
        Some(Arc::new(Self {
            socket,
            port,
            connections: RwLock::default(),
            clock: Clock::default(),
            receiving: AtomicBool::new(true),
            fragmentation,
        }))
    }

    /// Three `HashMap`s have no invariant a panic can break, so poison is ignored.
    fn read(&self) -> RwLockReadGuard<'_, Connections> {
        self.connections
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Connections> {
        self.connections
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Where one datagram belongs, in one acquisition and without writing.
    fn route(&self, cid: ConnectionId) -> Route {
        let connections = self.read();
        if let Some(live) = connections.live.get(&cid) {
            return Route::Live(Attached {
                wire: Arc::clone(&live.wire),
                handle: Arc::clone(&live.handle),
                id: live.id,
                peer: live.peer,
                width: datagram_width(live.limit.get()),
                version: live.version,
            });
        }
        if let Some(parting) = connections.parting.get(&cid) {
            return Route::Parting(Departing {
                wire: Arc::clone(&parting.wire),
                peer: parting.peer,
                width: datagram_width(parting.limit.get()),
            });
        }
        if connections.pending.contains_key(&cid) {
            return Route::Pending;
        }
        Route::Unknown
    }

    /// Mint the path one attachment may move onto. Per attachment: one cid and
    /// secret shared would let either attachment answer for the other.
    pub(crate) fn offer(&self) -> Option<DatagramOffer> {
        if !self.receiving.load(Ordering::Relaxed) {
            return None;
        }
        let cid = ConnectionId::random().ok()?;
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).ok()?;
        let now = Instant::now();
        self.write().pending.insert(
            cid,
            Pending {
                secret: RootSecret::new(secret),
                minted: now,
            },
        );
        // The transmit thread's to prune: a daemon may mint one offer and no more.
        self.clock.advance(now + OFFER_LIFETIME);
        Some(DatagramOffer {
            // The daemon does not know which of this host's addresses the client
            // reached; `brd --server` fills this in on the frame's way past.
            ip: [0; 16],
            port: self.port,
            cid: cid.as_bytes(),
            secret,
        })
    }

    /// Start the two threads this socket needs, and let a failure to start
    /// either one cost the datagram path rather than the daemon.
    pub(crate) fn serve(self: &Arc<Self>, daemon: &Arc<DaemonState>) {
        let receiving = Arc::clone(self);
        let sessions = Arc::clone(daemon);
        if thread::Builder::new()
            .name("brd-datagram".into())
            .spawn(move || receiving.receive(&sessions))
            .is_err()
        {
            log!("could not start the datagram receive thread");
            // A socket nobody reads must not be offered to anybody.
            self.receiving.store(false, Ordering::Relaxed);
        }
        let transmitting = Arc::clone(self);
        if thread::Builder::new()
            .name("brd-datagram-tx".into())
            .spawn(move || transmitting.transmit())
            .is_err()
        {
            log!("could not start the datagram transmit thread");
            self.receiving.store(false, Ordering::Relaxed);
        }
    }

    /// One reader for the whole daemon: a `SO_REUSEPORT` pool would multiply the
    /// admission rate by its size and buys throughput this path does not need.
    fn receive(self: &Arc<Self>, daemon: &Arc<DaemonState>) {
        let _serving = Serving::new(self, "receive");
        // Sized to the search's ceiling: a truncated datagram fails to authenticate.
        let mut buffer = [0u8; MAX_DATAGRAM];
        let mut scratch = Scratch::default();
        let mut limiter = Limiter::default();
        let mut failures = 0u32;
        loop {
            let (len, from) = match self.socket.recv_from(&mut buffer) {
                Ok(received) => {
                    failures = 0;
                    received
                }
                Err(error) if is_transient(error.kind()) => continue,
                Err(error) => {
                    failures += 1;
                    if failures < RECEIVE_ATTEMPTS {
                        thread::sleep(RECEIVE_BACKOFF);
                        continue;
                    }
                    log!("datagram receive failed {failures} times, giving up: {error}");
                    return;
                }
            };
            let Some(datagram) = buffer.get_mut(..len) else {
                continue;
            };
            let Ok(cid) = braid_dgram::peek(datagram) else {
                continue;
            };
            let arrival = Arrival {
                cid,
                from,
                at: Instant::now(),
            };
            match self.route(cid) {
                Route::Live(live) => self.deliver(arrival, &live, datagram, &mut scratch),
                Route::Parting(departing) => {
                    self.overhear(arrival, &departing, datagram, &mut scratch);
                }
                Route::Pending if limiter.admits(from.ip(), arrival.at) => {
                    self.admit(daemon, arrival, datagram, &mut scratch);
                }
                Route::Pending | Route::Unknown => {}
            }
        }
    }

    fn deliver(
        &self,
        arrival: Arrival,
        live: &Attached,
        datagram: &mut [u8],
        scratch: &mut Scratch,
    ) {
        // The cid travels in the clear, so an unvalidated address may cost this
        // session's wire lock no more than the path the connection already uses.
        if arrival.from != live.peer && datagram.len() > live.width {
            return;
        }
        let (delivery, moved, next) = {
            let mut guard = wire(&live.wire);
            let Wire { endpoint, .. } = &mut *guard;
            let mut moved = None;
            let delivery = match endpoint.recv(arrival.from, arrival.at, datagram) {
                Ok(Received::Frame(range)) => datagram
                    .get(range)
                    .and_then(|body| frame_message(body, live.version, &mut scratch.payload))
                    // As on a stream: a frame this side cannot restate ends the connection.
                    .map_or(Delivery::Retire, Delivery::Command),
                Ok(Received::Closed) => Delivery::Retire,
                Ok(Received::Migrated(to)) => {
                    log!(
                        "datagram path migrated to {to}: {}",
                        transport(&endpoint.stats())
                    );
                    moved = Some(to);
                    Delivery::Ignore
                }
                // Ordinary on a public network: an endpoint that died on a forged
                // packet would be a session anybody could end.
                Ok(Received::Nothing) | Err(_) => Delivery::Ignore,
            };
            // Now rather than on the next tick: an acknowledgement is what reopens
            // the sender's window and what its round-trip estimate is measured from.
            while scratch
                .outbound
                .seal(|out| endpoint.poll_transmit(arrival.at, out).map(|(to, _)| to))
            {}
            let next = endpoint.poll_deadline();
            guard.publish();
            (delivery, moved, next)
        };
        // Outside the connection's lock, all three: a full socket must not stall
        // under it, and the map is the lock a `Wire` is taken under, never after.
        if let Some(to) = moved {
            // Once per network change, so it can afford the write lock.
            if let Some(live) = self.write().live.get_mut(&arrival.cid) {
                live.peer = to;
            }
        }
        if let Some(next) = next {
            self.clock.advance(next);
        }
        scratch.outbound.flush(&self.socket);
        match delivery {
            Delivery::Ignore => {}
            Delivery::Command(message) => {
                // One thread receives for every session, so a blocking send here
                // is one busy actor stalling every other client's keystrokes.
                if let Err(TrySendError::Closed) = live.handle.tx.try_send(ActorEvent::Command {
                    id: live.id,
                    message,
                }) {
                    self.retire(arrival.cid);
                }
            }
            Delivery::Retire => self.retire(arrival.cid),
        }
    }

    /// Let a retiring connection hear its peer, without delivering anything: the
    /// acknowledgement reopening its farewell's window arrives here or nowhere.
    fn overhear(
        &self,
        arrival: Arrival,
        departing: &Departing,
        datagram: &mut [u8],
        scratch: &mut Scratch,
    ) {
        if arrival.from != departing.peer && datagram.len() > departing.width {
            return;
        }
        let next = {
            let mut guard = wire(&departing.wire);
            let Wire { endpoint, .. } = &mut *guard;
            let _ = endpoint.recv(arrival.from, arrival.at, datagram);
            while scratch
                .outbound
                .seal(|out| endpoint.poll_transmit(arrival.at, out).map(|(to, _)| to))
            {}
            endpoint.poll_deadline()
        };
        if let Some(next) = next {
            self.clock.advance(next);
        }
        scratch.outbound.flush(&self.socket);
    }

    /// Forget one connection and tell the actor its transport is gone, exactly
    /// once: the removal is what makes the send happen on one path only.
    fn retire(&self, cid: ConnectionId) {
        let now = Instant::now();
        let (handle, id) = {
            let mut connections = self.write();
            let Some(live) = connections.live.remove(&cid) else {
                return;
            };
            // Map first, then the connection, as `Connections` requires.
            let parting = {
                let mut wire = wire(&live.wire);
                log!(
                    "datagram connection retired: {}",
                    transport(&wire.endpoint.stats())
                );
                wire.retired = true;
                wire.farewell.is_some()
            };
            if parting {
                connections.parting.insert(
                    cid,
                    Parting {
                        wire: Arc::clone(&live.wire),
                        left: FAREWELL_REPEATS,
                        due: now,
                        expires: now + FAREWELL_WINDOW,
                        peer: live.peer,
                        limit: live.limit.clone(),
                    },
                );
            }
            (live.handle, live.id)
        };
        self.clock.advance(now);
        // `try_send`: this thread has no retry to offer. The wire is marked retired
        // above, so the attachment's next write fails and `tick` reaps it.
        let _ = handle.tx.try_send(ActorEvent::Detached(id));
    }

    /// Turn the first datagram of an offered connection into an attachment. Any
    /// path that leaves without restoring the offer has provably sealed under it.
    #[expect(
        clippy::too_many_lines,
        reason = "the offer is taken out at the top and every path below either restores it or has provably sealed under it: splitting that leaves the restore in a different function from the take"
    )]
    fn admit(
        self: &Arc<Self>,
        daemon: &Arc<DaemonState>,
        arrival: Arrival,
        datagram: &mut [u8],
        scratch: &mut Scratch,
    ) {
        let Some(offer) = self.write().pending.remove(&arrival.cid) else {
            return;
        };
        let minted = offer.minted;
        let (accepted, received) = match Endpoint::accept(
            arrival.cid,
            offer.secret,
            arrival.from,
            arrival.at,
            datagram,
            self.fragmentation,
        ) {
            Ok(opened) => opened,
            Err(refused) => {
                // A client whose first attempt was lost retries inside its probe budget.
                self.restore(arrival.cid, refused.root, minted);
                return;
            }
        };
        let Received::Frame(range) = received else {
            self.restore(arrival.cid, accepted.release(), minted);
            return;
        };
        // An ordinary resume, which is what makes it replace the ssh attachment
        // carrying the same `ClientId`. Read at LOCAL: it carries the range.
        let Some(ClientMessage::Resume {
            versions, request, ..
        }) = datagram
            .get(range)
            .and_then(|body| frame_message(body, Version::LOCAL, &mut scratch.payload))
        else {
            self.restore(arrival.cid, accepted.release(), minted);
            return;
        };
        let version = match VersionRange::LOCAL.negotiate(versions) {
            Ok(version) => version,
            Err(reason) => {
                let mut endpoint = accepted.commit();
                self.answer(
                    &mut endpoint,
                    arrival.at,
                    Version::LOCAL,
                    &ServerMessage::Reject { reason },
                );
                return;
            }
        };
        let session = match load_ticket(request.session_id, request.capability) {
            // Wrapped once here so [`Live::handle`] costs an increment per datagram.
            Ok(ticket) => registry(daemon)
                .sessions
                .get(&ticket.session_id)
                .cloned()
                .map(Arc::new),
            Err(_) => None,
        };
        let Some(handle) = session else {
            // Refused in the protocol, as the stream path refuses it. The offer is
            // not restored: this answer is a real datagram sealed under its keys.
            let mut endpoint = accepted.commit();
            self.answer(
                &mut endpoint,
                arrival.at,
                version,
                &ServerMessage::Reject {
                    reason: RejectReason::UnknownSession,
                },
            );
            return;
        };
        let endpoint = accepted.commit();
        let limit = PayloadLimit::fixed(frame_budget(endpoint.payload_limit()));
        let shared = Arc::new(Mutex::new(Wire {
            endpoint,
            farewell: None,
            retired: false,
            limit: limit.clone(),
            reported: Reported::default(),
        }));
        let Ok(sink) = AttachmentSink::new(
            DatagramWriter::new(Arc::clone(self), arrival.cid, Arc::clone(&shared)),
            version,
        ) else {
            // Cannot restore: the sink needs the endpoint the offer produced.
            return;
        };
        let id = AttachmentId(NEXT_ATTACHMENT.fetch_add(1, Ordering::Relaxed));
        self.write().live.insert(
            arrival.cid,
            Live {
                wire: shared,
                handle: Arc::clone(&handle),
                id,
                peer: arrival.from,
                limit: limit.clone(),
                version,
            },
        );
        // A connection admitted after the thread slept owes a challenge nobody sends.
        self.clock.advance(arrival.at);
        // `try_send`, as everywhere on this thread; the refused event drops the sink.
        if handle
            .tx
            .try_send(ActorEvent::Attach {
                id,
                client: request.client,
                sink,
                kind: AttachKind::Resume(request.confirmed_output),
                framing: Framing::Datagram { budget: limit },
                // A client already on this path has nowhere further to move.
                offer: None,
            })
            .is_err()
        {
            self.write().live.remove(&arrival.cid);
        }
    }

    /// Put an offer back, having sealed nothing under it. The original `minted`
    /// goes with it, so a stray datagram cannot renew an offer's expiry.
    fn restore(&self, cid: ConnectionId, secret: RootSecret, minted: Instant) {
        self.write().pending.insert(cid, Pending { secret, minted });
    }

    /// Say one thing to a peer that is not going to become an attachment.
    fn answer(
        &self,
        endpoint: &mut Endpoint,
        now: Instant,
        spoken: Version,
        message: &ServerMessage,
    ) {
        let Ok(frame) = message.encode(spoken) else {
            return;
        };
        let Some(payload) = frame.get(FRAME_LENGTH_PREFIX..) else {
            return;
        };
        let mut body = Vec::new();
        pack(payload, &mut body);
        let mut sealed = Vec::new();
        let Ok(to) = endpoint.send(&body, now, &mut sealed) else {
            return;
        };
        let _ = self.socket.send_to(&sealed, to);
    }

    fn transmit(self: &Arc<Self>) {
        let _serving = Serving::new(self, "transmit");
        let mut outbound = Outbound::default();
        // Kept between ticks so walking the map costs no allocation.
        let mut wires: Vec<Arc<Mutex<Wire>>> = Vec::new();
        loop {
            let deadline = self.tick(Instant::now(), &mut outbound, &mut wires);
            // Outside every lock: an `ENOBUFS` stall must not hold the map.
            outbound.flush(&self.socket);
            // From the end of the tick: an earlier floor would name an instant past.
            self.clock
                .sleep_until(deadline.max(Instant::now() + POLL_FLOOR));
        }
    }

    /// One pass over every connection, and when the next one is owed.
    fn tick(
        &self,
        now: Instant,
        outbound: &mut Outbound,
        wires: &mut Vec<Arc<Mutex<Wire>>>,
    ) -> Instant {
        let mut deadline = now + POLL_INTERVAL;
        // A read guard is all a steady state needs: both maps below are empty
        // then, and a write guard shuts out the thread that receives for every
        // session for the whole walk, a parting connection's seal included.
        let owed = {
            let connections = self.read();
            wires.extend(connections.live.values().map(|live| Arc::clone(&live.wire)));
            !connections.pending.is_empty() || !connections.parting.is_empty()
        };
        if owed {
            let mut connections = self.write();
            let Connections {
                pending, parting, ..
            } = &mut *connections;
            pending.retain(|_, offer| {
                let expires = offer.minted + OFFER_LIFETIME;
                if expires <= now {
                    // Dropping the entry scrubs its secret.
                    return false;
                }
                deadline = deadline.min(expires);
                true
            });
            parting.retain(|_, parting| {
                if parting.expires <= now {
                    return false;
                }
                let mut guard = wire(&parting.wire);
                // Through the guard once: a `MutexGuard` derefs as a whole.
                let Wire {
                    endpoint, farewell, ..
                } = &mut *guard;
                let Some(body) = farewell.as_deref() else {
                    return false;
                };
                // On every tick, not only when a copy is due: this retires what the
                // peer never acknowledged, and a window holding it refuses the farewell.
                while outbound.seal(|out| endpoint.poll_transmit(now, out).map(|(to, _)| to)) {}
                if let Some(next) = endpoint.poll_deadline() {
                    deadline = deadline.min(next);
                }
                if now >= parting.due {
                    if outbound.seal(|out| endpoint.send(body, now, out).ok()) {
                        parting.left -= 1;
                        parting.due = now + FAREWELL_SPACING;
                    } else {
                        // `ready` is when the window would not refuse it.
                        parting.due = endpoint
                            .ready(now, body.len())
                            .unwrap_or(now + FAREWELL_SPACING);
                    }
                }
                deadline = deadline.min(parting.due.min(parting.expires));
                parting.left > 0
            });
        }
        for shared in wires.drain(..) {
            let mut guard = wire(&shared);
            let Wire { endpoint, .. } = &mut *guard;
            // Each poll produces at most one datagram, so this drains rather than spins.
            while outbound.seal(|out| endpoint.poll_transmit(now, out).map(|(to, _)| to)) {}
            if let Some(next) = endpoint.poll_deadline() {
                deadline = deadline.min(next);
            }
            guard.publish();
        }
        deadline
    }
}

/// Slots kept between ticks. One tick seals for every live connection before it
/// flushes, so the high-water mark is a whole burst's worth of `MAX_DATAGRAM`
/// buffers - resident memory no attachment ceiling charges for, which nothing
/// here would otherwise ever give back. Past this a burst allocates and frees
/// rather than pinning its peak for the daemon's life; up to it the steady
/// state still recycles every buffer.
const OUTBOUND_SLOTS: usize = 64;

/// Datagrams sealed under a lock and sent once it is released: sealing is
/// arithmetic, sending is a syscall, and only the first needs the connection.
#[derive(Default)]
struct Outbound {
    slots: Vec<(SocketAddr, Vec<u8>)>,
    /// How many of `slots` this tick filled. The rest keep their capacity.
    filled: usize,
}

impl Outbound {
    /// Seal one datagram into the batch; false when there was none to seal.
    fn seal(&mut self, into: impl FnOnce(&mut Vec<u8>) -> Option<SocketAddr>) -> bool {
        if self.filled == self.slots.len() {
            // The search's ceiling, not the path's floor: `poll_transmit` emits MTU
            // probes of up to `MAX_DATAGRAM`, and a grown slot keeps that capacity.
            self.slots.push((
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                Vec::with_capacity(MAX_DATAGRAM),
            ));
        }
        let Some((to, datagram)) = self.slots.get_mut(self.filled) else {
            return false;
        };
        datagram.clear();
        let Some(peer) = into(datagram) else {
            return false;
        };
        *to = peer;
        self.filled += 1;
        true
    }

    /// One `send_to` each rather than `sendmmsg`, measured on a 5950X with 64-byte
    /// datagrams: 1284ns against 1375 at a batch of one, the case that matters.
    fn flush(&mut self, socket: &UdpSocket) {
        for (to, datagram) in self.slots.iter().take(self.filled) {
            let _ = socket.send_to(datagram, *to);
        }
        self.filled = 0;
        self.slots.truncate(OUTBOUND_SLOTS);
    }
}

/// One connection's endpoint, whatever a panicked thread left: a half-sealed
/// datagram costs a packet number, and the peer's replay window accepts a gap.
fn wire(held: &Mutex<Wire>) -> MutexGuard<'_, Wire> {
    held.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether one `recv_from` failure is worth another read. The unreachable and reset
/// kinds are ICMP errors for datagrams this socket sent, which Windows reports here.
fn is_transient(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

/// Whether a send failed because the path refuses a datagram this wide: loss the
/// MTU search narrows for, not a broken socket.
fn path_refused(error: &io::Error) -> bool {
    error.raw_os_error() == Some(rustix::io::Errno::MSGSIZE.raw_os_error())
}

/// Tell the connection what the kernel says this path carries, rather than let
/// the search spend three losses and two spaced probes — seconds of output down
/// a black hole — rediscovering the width the ICMP behind this refusal already
/// named. Only this side's own `sendto` reaches here and no arriving datagram
/// does, so unlike a loss a forged packet cannot drive it.
#[cfg(target_os = "linux")]
fn narrowed(held: &Mutex<Wire>, to: SocketAddr, now: Instant) {
    let Some(carries) = path_mtu(to) else {
        return;
    };
    let mut guard = wire(held);
    guard.endpoint.path_refused(carries, now);
    guard.publish();
}

/// What the route says a datagram to this peer may carry. The number is the
/// route's rather than the socket's, and `IP_MTU` on the daemon's unconnected
/// socket is `ENOTCONN`, so a throwaway connected socket is what reads the very
/// value the refused `sendto` was measured against: four syscalls, on a path
/// taken once per narrowing.
#[cfg(target_os = "linux")]
fn path_mtu(to: SocketAddr) -> Option<usize> {
    /// What the kernel's MTU counts and a datagram's own width does not.
    const V4_HEADERS: usize = 20 + 8;
    const V6_HEADERS: usize = 40 + 8;

    let probe = match to {
        SocketAddr::V4(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)),
    }
    .ok()?;
    probe.connect(to).ok()?;
    let mtu = match to {
        SocketAddr::V4(_) => rustix::net::sockopt::ip_mtu(&probe),
        SocketAddr::V6(_) => rustix::net::sockopt::ipv6_mtu(&probe),
    }
    .ok()?;
    // The headers a v4-mapped peer's datagrams really leave with, not the ones
    // the family of the socket they were handed to would suggest.
    let headers = match to.ip() {
        IpAddr::V4(_) => V4_HEADERS,
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => V4_HEADERS,
        IpAddr::V6(_) => V6_HEADERS,
    };
    usize::try_from(mtu).ok()?.checked_sub(headers)
}

/// The loss-driven search is the only route here: `IP_DONTFRAG` refuses an
/// oversize datagram without naming a width, and no route MTU can be read back.
#[cfg(not(target_os = "linux"))]
fn narrowed(_: &Mutex<Wire>, _: SocketAddr, _: Instant) {}

/// Whether this payload is the last thing an attachment will be told. By tag, not
/// by decoding: this runs on every frame, and a screen is the largest one there is.
fn is_farewell(payload: &[u8]) -> bool {
    const EXIT: u8 = 0x84;
    const REJECT: u8 = 0x85;
    const DETACHED: u8 = 0x87;
    payload
        .first()
        .is_some_and(|tag| matches!(*tag, EXIT | REJECT | DETACHED))
}

/// Decode one datagram's body as a client message. `unpack` is the length check that
/// matters: a datagram knows its own length, so what is bounded is what it inflates to.
fn frame_message(body: &[u8], spoken: Version, payload: &mut Vec<u8>) -> Option<ClientMessage> {
    unpack(body, MAX_CLIENT_FRAME as usize, payload).ok()?;
    ClientMessage::decode(payload, spoken).ok()
}

/// What one frame's turn at the wire achieved.
enum Sealing {
    Sent,
    /// The window or the pacer refuses this frame *now*; nothing was consumed.
    Blocked,
    /// The path shrank below a frame that was already cut to fit it. That is output
    /// loss, repaired above; retiring instead would take the session's inbound half.
    Outgrown,
}

/// The sink's transport for one datagram attachment: one `braid` frame per datagram,
/// so `emit` walks a concatenated batch back apart along its length prefixes.
struct DatagramWriter {
    listener: Arc<DatagramListener>,
    cid: ConnectionId,
    /// Held directly: a lookup would be a daemon-wide lock per outgoing datagram.
    wire: Arc<Mutex<Wire>>,
    /// One failure fails every later write. A refusal for want of window is not one
    /// of those failures and never sets this.
    failed: bool,
    /// Kept across writes so a session's output does not allocate two buffers a frame.
    packed: Vec<u8>,
    sealed: Vec<u8>,
    /// Reported once per connection: the queue holds a quarter of a megabyte.
    outgrown: bool,
}

impl DatagramWriter {
    fn new(listener: Arc<DatagramListener>, cid: ConnectionId, wire: Arc<Mutex<Wire>>) -> Self {
        Self {
            listener,
            cid,
            wire,
            failed: false,
            packed: Vec::with_capacity(BASE_DATAGRAM),
            sealed: Vec::with_capacity(BASE_DATAGRAM),
            outgrown: false,
        }
    }

    /// Send as much of `batch` as the window admits, and say how much that was.
    fn emit(&mut self, batch: &[u8], coding: Coding, now: Instant) -> io::Result<usize> {
        let mut at = 0;
        while at < batch.len() {
            let prefix: [u8; FRAME_LENGTH_PREFIX] = batch
                .get(at..at + FRAME_LENGTH_PREFIX)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| io::Error::other("a batch ended inside a frame header"))?;
            let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(io::Error::other)?;
            let end = at + FRAME_LENGTH_PREFIX + length;
            // The payload alone: the stream framing's prefix is redundant with the
            // datagram's own length, so `pack`'s tag takes its place.
            let payload = batch
                .get(at + FRAME_LENGTH_PREFIX..end)
                .ok_or_else(|| io::Error::other("a batch ended inside a frame"))?;
            match self.seal(payload, coding, now)? {
                // Offering an outgrown frame again would park this sink for ever.
                Sealing::Sent | Sealing::Outgrown => at = end,
                Sealing::Blocked => break,
            }
        }
        Ok(at)
    }

    /// `Coding::Packed` is a payload the cut has packed: a screen, whose pieces
    /// had to go through the codec to be measured against the path in the first
    /// place. Only a screen ever arrives that way, and a screen is never the
    /// last thing an attachment is told, which is why the farewell check may
    /// skip it - the first byte of a packed payload is the codec's tag, not the
    /// message's.
    fn seal(&mut self, payload: &[u8], coding: Coding, now: Instant) -> io::Result<Sealing> {
        let Self {
            listener,
            wire: held,
            packed,
            sealed,
            outgrown,
            ..
        } = self;
        let to = {
            let mut guard = wire(held);
            if guard.retired {
                return Err(io::Error::other("the datagram connection is gone"));
            }
            // Recorded before anything can refuse it: a session that ends while its
            // window is full would otherwise report a close it never transmitted.
            let last = coding == Coding::Raw && is_farewell(payload);
            let Wire {
                endpoint, farewell, ..
            } = &mut *guard;
            let wire_bytes = match coding {
                // Already the bytes the datagram carries, so there is nothing to
                // estimate and nothing left to compress.
                Coding::Packed => {
                    if !endpoint.writable(now, payload.len()) {
                        return Ok(Sealing::Blocked);
                    }
                    payload
                }
                Coding::Raw => {
                    // The upper bound `pack` can produce.
                    let bound = payload.len() + PACK_TAG;
                    let fits_raw = bound <= endpoint.payload_limit();
                    // A frame the *path* cannot carry must never park on the window;
                    // one that fits raw is asked about before compressing, which the
                    // window may waste.
                    if !last && fits_raw && !endpoint.writable(now, bound) {
                        return Ok(Sealing::Blocked);
                    }
                    pack(payload, packed);
                    // One that does not fit raw was cut against what it compresses
                    // to, so the packed size is the only honest thing to ask the
                    // window about.
                    if !last && !fits_raw && !endpoint.writable(now, packed.len()) {
                        return Ok(Sealing::Blocked);
                    }
                    packed
                }
            };
            if last {
                *farewell = Some(wire_bytes.to_vec());
            }
            sealed.clear();
            match endpoint.send(wire_bytes, now, sealed) {
                Ok(to) => to,
                // An acknowledgement can shrink the window between the two calls.
                Err(SendError::Blocked) => return Ok(Sealing::Blocked),
                Err(SendError::TooLarge { actual, limit }) => {
                    if !*outgrown {
                        *outgrown = true;
                        log!(
                            "this path narrowed to {limit} bytes under a {actual}-byte frame \
                             already cut for a wider one; what was queued for it is being dropped"
                        );
                    }
                    return Ok(Sealing::Outgrown);
                }
                Err(error) => return Err(io::Error::other(error)),
            }
        };
        match listener.socket.send_to(sealed, to) {
            Ok(_) => Ok(Sealing::Sent),
            // The frame is gone either way, and reporting it as a write failure
            // would end an attachment over a path the search can still fit.
            Err(error) if path_refused(&error) => {
                // A refusal of a datagram at the floor is nothing the search can
                // answer: there is no width under it to narrow to.
                if sealed.len() > BASE_DATAGRAM {
                    narrowed(held, to, now);
                }
                Ok(Sealing::Sent)
            }
            Err(error) => Err(error),
        }
    }
}

/// `FrameWriter` rather than `Write`: this transport needs to be told which
/// frames are already packed, and the blanket `Write` impl has nowhere to say it.
impl FrameWriter for DatagramWriter {
    /// The frames already apart, and one clock for all of them: frames timed a
    /// microsecond apart are round-trip samples that disagree about when the
    /// batch left. Every return lands on a frame boundary, so the sink resumes
    /// at that frame rather than inside it.
    fn write_frames(&mut self, frames: &[IoSlice<'_>], packed: FrameSet) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("the datagram connection is gone"));
        }
        let now = Instant::now();
        let mut consumed = 0;
        for (index, frame) in frames.iter().enumerate() {
            let coding = if packed.contains(index) {
                Coding::Packed
            } else {
                Coding::Raw
            };
            match self.emit(frame, coding, now) {
                Ok(taken) => {
                    consumed += taken;
                    if taken < frame.len() {
                        break;
                    }
                }
                Err(error) => {
                    self.failed = true;
                    return Err(error);
                }
            }
        }
        if consumed > 0 {
            Ok(consumed)
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    /// Nothing is buffered: a datagram is written the moment it is sealed.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A connection lives exactly as long as the sink that writes to it: without this
/// the entry would keep a session's keep-alives flowing to a gone attachment.
impl Drop for DatagramWriter {
    fn drop(&mut self) {
        self.listener.retire(self.cid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_offer;
    use crate::dgram;
    use crate::mailbox::{CONTROL_LANE, MailboxSender, mailbox};
    use crate::registry::{DaemonState, registry};
    use crate::testing::*;
    use crate::{FRAME_LENGTH_PREFIX, sessions};
    use braid_proto::{
        ByteOff, Capability, CmdSeq, DetachReason, InputCue, MAX_FRAME, RejectReason,
    };
    use braid_proto::{ClientMessage, ServerMessage, Version, VersionRange};
    use std::panic::{self, AssertUnwindSafe};

    /// A peer that is a real socket, so what the writer sends can be counted.
    struct Peer {
        socket: UdpSocket,
        endpoint: Endpoint,
        address: SocketAddr,
    }

    impl Peer {
        fn new(cid: ConnectionId, secret: [u8; 32]) -> Self {
            let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("a peer socket");
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("a read timeout");
            let address = socket.local_addr().expect("a bound port");
            Self {
                socket,
                endpoint: Endpoint::connect(
                    cid,
                    RootSecret::new(secret),
                    address,
                    Fragmentation::Refused,
                ),
                address,
            }
        }

        /// The same, aimed at a daemon that is really listening on `daemon`.
        fn dialling(cid: ConnectionId, secret: [u8; 32], daemon: SocketAddr) -> Self {
            let mut peer = Self::new(cid, secret);
            peer.endpoint =
                Endpoint::connect(cid, RootSecret::new(secret), daemon, Fragmentation::Refused);
            peer
        }

        /// Every datagram waiting, opened and unpacked into server messages.
        fn drain(&mut self) -> Vec<ServerMessage> {
            let mut datagram = vec![0u8; MAX_DATAGRAM];
            let mut payload = Vec::new();
            let mut messages = Vec::new();
            while let Ok((len, from)) = self.socket.recv_from(&mut datagram) {
                let now = Instant::now();
                let Ok(Received::Frame(range)) =
                    self.endpoint.recv(from, now, &mut datagram[..len])
                else {
                    continue;
                };
                unpack(&datagram[range], MAX_FRAME as usize, &mut payload)
                    .expect("a datagram body unpacks");
                messages.push(
                    ServerMessage::decode(&payload, Version::LOCAL).expect("a message decodes"),
                );
            }
            messages
        }

        /// The `(epoch, number)` of every datagram waiting, read off the clear
        /// header: a repeated pair is a repeated keystream, visible without a key.
        fn nonces(&self) -> Vec<(u8, u64)> {
            let mut datagram = vec![0u8; MAX_DATAGRAM];
            let mut seen = Vec::new();
            while let Ok((len, _)) = self.socket.recv_from(&mut datagram) {
                let header = braid_dgram::packet::Header::decode(&datagram[..len])
                    .expect("a datagram header");
                seen.push((header.epoch.get(), header.number));
            }
            seen
        }
    }

    /// One live connection on `listener`, its wire, and the peer it talks to.
    fn live_connection(
        listener: &DatagramListener,
        tx: MailboxSender,
    ) -> (ConnectionId, Peer, Arc<Mutex<Wire>>) {
        let (cid, mut peer, shared) = claimed_connection(listener, tx);
        validate(&shared, &mut peer);
        (cid, peer, shared)
    }

    /// The same, with the peer's address still only a claim.
    fn claimed_connection(
        listener: &DatagramListener,
        tx: MailboxSender,
    ) -> (ConnectionId, Peer, Arc<Mutex<Wire>>) {
        let cid = ConnectionId::random().expect("a connection id");
        let secret = [7u8; 32];
        let peer = Peer::new(cid, secret);
        let endpoint = Endpoint::listen(
            cid,
            RootSecret::new(secret),
            peer.address,
            listener.fragmentation,
        );
        let limit = PayloadLimit::fixed(frame_budget(endpoint.payload_limit()));
        let shared = Arc::new(Mutex::new(Wire {
            endpoint,
            farewell: None,
            retired: false,
            limit: limit.clone(),
            reported: Reported::default(),
        }));
        listener.write().live.insert(
            cid,
            Live {
                version: Version::LOCAL,
                wire: Arc::clone(&shared),
                handle: Arc::new(detached_handle(tx)),
                id: AttachmentId(1),
                peer: peer.address,
                limit,
            },
        );
        (cid, peer, shared)
    }

    /// A connection that retired owing its last word, and the peer it owes it to.
    fn parting_connection(
        listener: &Arc<DatagramListener>,
        tx: MailboxSender,
    ) -> (ConnectionId, Peer, Arc<Mutex<Wire>>) {
        let (cid, peer, shared) = live_connection(listener, tx);
        let mut writer = DatagramWriter::new(Arc::clone(listener), cid, Arc::clone(&shared));
        let farewell = ServerMessage::Exit { code: 0 }
            .encode(Version::LOCAL)
            .expect("a farewell encodes");
        assert_eq!(
            writer
                .write_frames(&[IoSlice::new(&farewell)], FrameSet::default())
                .expect("an open window carries the farewell"),
            farewell.len(),
            "the whole frame went"
        );
        drop(writer);
        (cid, peer, shared)
    }

    /// Prove the peer's address to a listening endpoint, off the socket: what
    /// these tests count is the datagrams a *session* produces.
    fn validate(shared: &Arc<Mutex<Wire>>, peer: &mut Peer) {
        use braid_dgram::packet::{Header, Kind};
        let now = Instant::now();
        let mut arriving = keystroke(peer);
        wire(shared)
            .endpoint
            .recv(peer.address, now, &mut arriving)
            .expect("the peer's first datagram opens");
        let mut challenge = Vec::new();
        loop {
            challenge.clear();
            assert!(
                wire(shared)
                    .endpoint
                    .poll_transmit(now, &mut challenge)
                    .is_some(),
                "a listening endpoint challenges the address it was handed"
            );
            if Header::decode(&challenge).expect("a datagram header").kind == Kind::Challenge {
                break;
            }
        }
        peer.endpoint
            .recv(peer.address, now, &mut challenge)
            .expect("the challenge opens");
        let mut response = Vec::new();
        peer.endpoint
            .poll_transmit(now, &mut response)
            .expect("the peer answers the challenge");
        wire(shared)
            .endpoint
            .recv(peer.address, now, &mut response)
            .expect("the answer proves the address");
    }

    /// The route a datagram from `peer` takes, as the receive loop resolves it.
    fn arrival(cid: ConnectionId, peer: &Peer) -> Arrival {
        Arrival {
            cid,
            from: peer.address,
            at: Instant::now(),
        }
    }

    fn attached(route: Route) -> Attached {
        match route {
            Route::Live(live) => live,
            Route::Parting(_) | Route::Pending | Route::Unknown => {
                panic!("the connection is live")
            }
        }
    }

    fn departing(route: Route) -> Departing {
        match route {
            Route::Parting(departing) => departing,
            Route::Live(_) | Route::Pending | Route::Unknown => {
                panic!("the connection is retiring")
            }
        }
    }

    /// One frame packed and sealed as the client half sends it.
    fn sealed(peer: &mut Peer, frame: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        pack(&frame[FRAME_LENGTH_PREFIX..], &mut body);
        let mut datagram = Vec::new();
        peer.endpoint
            .send(&body, Instant::now(), &mut datagram)
            .expect("the frame seals");
        datagram
    }

    /// One keystroke, sealed by the client half.
    fn keystroke(peer: &mut Peer) -> Vec<u8> {
        let frame = ClientMessage::Input {
            seq: CmdSeq::first(),
            bytes: b"x".to_vec(),
        }
        .encode(Version::LOCAL)
        .expect("encode one keystroke");
        sealed(peer, &frame)
    }

    /// One datagram sealed as wide as the peer's path carries: a keystroke padded
    /// to the limit, since what is bounded is the datagram's length.
    fn widest_datagram(peer: &mut Peer) -> Vec<u8> {
        let frame = ClientMessage::Input {
            seq: CmdSeq::first(),
            bytes: b"x".to_vec(),
        }
        .encode(Version::LOCAL)
        .expect("encode one keystroke");
        let mut body = Vec::new();
        pack(&frame[FRAME_LENGTH_PREFIX..], &mut body);
        body.resize(peer.endpoint.payload_limit(), 0);
        let mut datagram = Vec::new();
        peer.endpoint
            .send(&body, Instant::now(), &mut datagram)
            .expect("seal a datagram the path is wide enough for");
        datagram
    }

    /// A batch as `AttachmentSink` builds one: whole frames behind length prefixes.
    fn batch(frames: &[Vec<u8>]) -> Vec<u8> {
        frames.iter().flatten().copied().collect()
    }

    /// An `Output` frame of `bytes` payload bytes that deflate cannot win on.
    fn incompressible(bytes: usize) -> Vec<u8> {
        let mut noise = vec![0u8; bytes];
        getrandom::fill(&mut noise).expect("entropy");
        output(noise)
    }

    fn output(bytes: Vec<u8>) -> Vec<u8> {
        message(bytes)
            .encode(Version::LOCAL)
            .expect("an output frame")
    }

    fn message(bytes: Vec<u8>) -> ServerMessage {
        ServerMessage::Output {
            off: ByteOff::zero(),
            bytes,
            cue: InputCue::Opaque,
            echo_ack: None,
        }
    }

    /// A busy actor is not a dead one: a command that finds the control lane full
    /// is dropped and the client's journal replays it, while an actor that is gone
    /// leaves this connection nothing to reach.
    #[test]
    fn a_full_queue_keeps_a_connection_and_a_dead_actor_retires_it() {
        for alive in [true, false] {
            let listener = DatagramListener::bind().expect("a datagram socket");
            let (tx, rx) = mailbox();
            if alive {
                for _ in 0..CONTROL_LANE {
                    tx.try_send(ActorEvent::Detached(AttachmentId(0)))
                        .expect("a free control slot");
                }
            } else {
                // The actor owns the receiving half.
                drop(rx);
            }
            let (cid, mut peer, _wire) = live_connection(&listener, tx);

            let mut datagram = keystroke(&mut peer);
            let live = attached(listener.route(cid));
            listener.deliver(
                arrival(cid, &peer),
                &live,
                &mut datagram,
                &mut Scratch::default(),
            );

            assert_eq!(
                listener.read().live.contains_key(&cid),
                alive,
                "a momentarily full queue cost the client its path, or a connection \
                 outlived the session it was serving"
            );
        }
    }

    /// A client that takes a path nothing reads burns its whole probe budget.
    #[test]
    fn a_listener_that_stopped_receiving_offers_nothing() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        assert!(listener.offer().is_some(), "a live socket offers its path");
        listener.receiving.store(false, Ordering::Relaxed);
        assert!(
            listener.offer().is_none(),
            "an offer outlived the thread that would have answered it"
        );
    }

    /// Read back off the socket rather than trusted to a `setsockopt` that returned
    /// `Ok`: what the search depends on is the option being in force.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_daemon_socket_refuses_to_fragment() {
        use rustix::net::sockopt::{Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};

        let listener = DatagramListener::bind().expect("a datagram socket");
        let socket = &listener.socket;
        assert_eq!(
            rustix::net::sockopt::ip_mtu_discover(socket).expect("IP_MTU_DISCOVER reads back"),
            Ipv4PathMtuDiscovery::DO,
            "a v4-mapped peer leaves through the v4 output path and reads this one"
        );
        if socket.local_addr().expect("a bound socket").is_ipv6() {
            assert_eq!(
                rustix::net::sockopt::ipv6_mtu_discover(socket)
                    .expect("IPV6_MTU_DISCOVER reads back"),
                Ipv6PathMtuDiscovery::DO
            );
        }
    }

    /// `EMSGSIZE` is the ordinary answer of a path that narrowed and must not read
    /// as the socket failing, so it is told apart by the errno the kernel produces.
    #[test]
    fn a_datagram_the_path_refuses_is_not_a_dead_socket() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a peer");
        let error = socket
            .send_to(&vec![0; 70_000], peer.local_addr().expect("a bound port"))
            .expect_err("a datagram past the UDP maximum goes nowhere");
        assert!(path_refused(&error));
        assert!(!path_refused(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
    }

    /// The width is the route's and not the socket's: read off the socket every
    /// session shares, which is unconnected, the kernel answers `ENOTCONN` and a
    /// narrowed path would learn nothing. What comes back is a payload, so the
    /// headers are checked against the kernel by sending exactly that much.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_width_a_path_carries_is_read_off_the_route_rather_than_the_socket() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let local = listener.socket.local_addr().expect("a bound socket");
        let (unconnected, peer) = match local {
            SocketAddr::V4(_) => (
                rustix::net::sockopt::ip_mtu(&listener.socket).is_err(),
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)),
            ),
            SocketAddr::V6(_) => (
                rustix::net::sockopt::ipv6_mtu(&listener.socket).is_err(),
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)),
            ),
        };
        assert!(unconnected, "the daemon's socket knows no one path's width");
        let to = peer
            .expect("a peer socket")
            .local_addr()
            .expect("a bound port");
        let carries = path_mtu(to).expect("a route to loopback has a width");
        assert!(carries > BASE_DATAGRAM, "loopback carries past the floor");
        if listener.fragmentation == Fragmentation::Refused {
            listener
                .socket
                .send_to(&vec![0; carries], to)
                .expect("what the route says it carries goes whole");
            let error = listener
                .socket
                .send_to(&vec![0; carries + 1], to)
                .expect_err("and one byte more does not");
            assert!(path_refused(&error), "by the errno the search reads");
        }
    }

    /// The tags [`is_farewell`] knows, against the encoder that writes them.
    /// [`MIN_DATAGRAM_FRAME`] floors every budget this daemon publishes and
    /// every one of these is smaller, so no narrowing can throw away the last
    /// word - and a truncated frame is neither a farewell nor an index panic.
    #[test]
    fn a_farewell_is_exactly_the_terminal_messages_and_always_fits_the_floor() {
        let mut terminal = vec![
            ServerMessage::Exit { code: 0 },
            ServerMessage::Exit { code: i32::MIN },
            ServerMessage::Detached {
                reason: DetachReason::Requested,
            },
            ServerMessage::Detached {
                reason: DetachReason::Replaced,
            },
        ];
        terminal.extend(
            [
                RejectReason::Version {
                    server: VersionRange::LOCAL,
                    client: VersionRange::LOCAL,
                },
                RejectReason::UnknownSession,
                RejectReason::SequenceGap,
                RejectReason::InputBacklog,
                RejectReason::Internal,
                RejectReason::TooManySessions,
                RejectReason::TooManyAttachments,
            ]
            .map(|reason| ServerMessage::Reject { reason }),
        );
        for message in &terminal {
            let frame = message.encode(Version::LOCAL).expect("a small message");
            assert!(
                is_farewell(&frame[FRAME_LENGTH_PREFIX..]),
                "{message:?} is the last word"
            );
            let mut packed = Vec::new();
            pack(&frame[FRAME_LENGTH_PREFIX..], &mut packed);
            assert!(
                packed.len() + PACK_TAG <= MIN_DATAGRAM_FRAME,
                "{message:?} packs to {} bytes, which a narrowed path could refuse",
                packed.len()
            );
        }

        let ordinary = [
            ServerMessage::CommandAck { highest: None },
            ServerMessage::Ping {
                token: 1,
                echo_ack: None,
                interval_ms: 250,
            },
        ];
        for message in &ordinary {
            let frame = message.encode(Version::LOCAL).expect("a small message");
            assert!(
                !is_farewell(&frame[FRAME_LENGTH_PREFIX..]),
                "{message:?} is repaired by what follows it"
            );
        }
        assert!(!is_farewell(&[]));
    }

    /// The whole send path over a real socket: packed, sealed, sent, opened, unpacked.
    #[test]
    fn a_frame_survives_the_packing_the_sealing_path_gives_it() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, mut peer, shared) = live_connection(&listener, tx);
        let mut writer = DatagramWriter::new(Arc::clone(&listener), cid, shared);

        // Larger than the path's raw budget, and still one datagram.
        let message = message(b"the same line over and over ".repeat(200));
        let frame = message.encode(Version::LOCAL).expect("an output frame");
        assert!(
            frame.len() > wire_limit(&writer),
            "the test frame is meant to need the compressor"
        );

        assert_eq!(
            writer
                .write_frames(&[IoSlice::new(&frame)], FrameSet::default())
                .expect("the frame goes"),
            frame.len(),
            "a frame the window admits is consumed whole"
        );
        assert_eq!(peer.drain(), vec![message]);
    }

    fn wire_limit(writer: &DatagramWriter) -> usize {
        wire(&writer.wire).limit.get()
    }

    /// An incompressible `Output` frame of exactly `size` bytes, prefix included.
    /// The payload length moves the header's own length, so this converges on it.
    fn frame_of(size: usize) -> Vec<u8> {
        let mut bytes = size - FRAME_LENGTH_PREFIX;
        for _ in 0..8 {
            let frame = incompressible(bytes);
            if frame.len() == size {
                return frame;
            }
            bytes = (bytes + size) - frame.len();
        }
        panic!("no payload length lands on {size} bytes");
    }

    /// A drift between the published budget and what the wire seals is a screen the
    /// ledger cuts and the wire refuses.
    #[test]
    fn a_frame_at_the_published_budget_still_fits_one_datagram() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, mut peer, shared) = live_connection(&listener, tx);
        let mut writer = DatagramWriter::new(Arc::clone(&listener), cid, shared);
        let budget = wire_limit(&writer);
        assert!(budget >= MIN_DATAGRAM_FRAME);
        let frame = frame_of(budget);

        assert_eq!(
            writer
                .write_frames(&[IoSlice::new(&frame)], FrameSet::default())
                .expect("the frame goes"),
            frame.len(),
            "a frame at the published budget was refused by the path that published it"
        );
        assert_eq!(peer.drain().len(), 1, "one frame is one datagram");
    }

    /// A budget that moved between the cut and the send leaves queued frames too
    /// large. The frame is lost, which the layer above repairs; the connection is not.
    #[test]
    fn a_frame_the_path_outgrew_is_dropped_and_the_connection_carries_the_next_one() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, mut peer, shared) = live_connection(&listener, tx);
        let mut writer = DatagramWriter::new(Arc::clone(&listener), cid, shared);
        let budget = wire_limit(&writer);
        // Cut for a path that carried more than this one does.
        let stale = frame_of(budget + 64);
        let fresh = frame_of(budget);
        let batch = batch(&[stale.clone(), fresh.clone()]);

        assert_eq!(
            writer
                .write_frames(&[IoSlice::new(&batch)], FrameSet::default())
                .expect("an outgrown frame is not a dead transport"),
            batch.len(),
            "the sink was left holding a frame no window will ever admit"
        );
        assert!(
            !writer.failed,
            "one frame the path outgrew retired the writer"
        );
        assert!(
            matches!(listener.route(cid), Route::Live(_)),
            "the connection was retired, so everything the client sends now routes nowhere"
        );
        assert_eq!(
            peer.drain().len(),
            1,
            "the frame cut to the path this connection has did not go out behind the one it outgrew"
        );
    }

    /// A batch the window cannot take whole must account for the part it did: the
    /// sink resends from the byte this returns, so a refusal that forgot its prefix
    /// sends those frames a second time. The vectored form promises the same.
    #[test]
    fn a_batch_the_window_refuses_reports_the_whole_frames_it_took() {
        for vectored in [false, true] {
            let listener = DatagramListener::bind().expect("a datagram socket");
            let (tx, _rx) = mailbox();
            let (cid, mut peer, shared) = live_connection(&listener, tx);
            let mut writer = DatagramWriter::new(Arc::clone(&listener), cid, shared);
            // Comfortably past the initial congestion window, in frames the
            // compressor cannot shrink.
            let frame = incompressible(1000);
            let frames = vec![frame.clone(); 64];
            let flat = batch(&frames);
            let slices: Vec<IoSlice<'_>> = frames.iter().map(|frame| IoSlice::new(frame)).collect();

            let consumed = if vectored {
                writer.write_frames(&slices, FrameSet::default())
            } else {
                writer.write_frames(&[IoSlice::new(&flat)], FrameSet::default())
            }
            .expect("a partial batch is not an error");
            assert!(
                consumed > 0 && consumed < flat.len(),
                "the initial window took the whole batch: {consumed} of {}",
                flat.len()
            );
            assert_eq!(
                consumed % frame.len(),
                0,
                "a batch was cut in the middle of a frame"
            );
            assert_eq!(
                peer.drain().len(),
                consumed / frame.len(),
                "the bytes reported consumed are not the frames that were sent"
            );

            let refused = if vectored {
                writer.write_frames(&slices[consumed / frame.len()..], FrameSet::default())
            } else {
                writer.write_frames(&[IoSlice::new(&flat[consumed..])], FrameSet::default())
            }
            .expect_err("the window is still shut");
            assert_eq!(refused.kind(), io::ErrorKind::WouldBlock);
            assert!(
                !writer.failed,
                "backpressure retired an attachment that was merely waiting"
            );
        }
    }

    /// The frame that carried it was refused, and `Parting` is what says it again.
    #[test]
    fn a_farewell_blocked_by_congestion_is_still_recorded() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, _peer, shared) = live_connection(&listener, tx);
        let mut writer = DatagramWriter::new(Arc::clone(&listener), cid, Arc::clone(&shared));
        let farewell = ServerMessage::Detached {
            reason: DetachReason::Requested,
        }
        .encode(Version::LOCAL)
        .expect("a farewell encodes");
        // Filled with the farewell frame itself: a larger filler leaves room a
        // two-byte message still fits into.
        while writer
            .write_frames(&[IoSlice::new(&farewell)], FrameSet::default())
            .is_ok()
        {}
        // What those copies recorded is not what is being proved.
        wire(&shared).farewell = None;

        let refused = writer
            .write_frames(&[IoSlice::new(&farewell)], FrameSet::default())
            .expect_err("the window is shut for the farewell too");

        assert_eq!(refused.kind(), io::ErrorKind::WouldBlock);
        assert!(
            wire(&shared).farewell.is_some(),
            "a session that ended while congested reported a close it never transmitted"
        );
    }

    /// Without a route of its own a retired connection is deaf, so the window its
    /// farewell was refused by never reopens and a clean detach reads as a hang.
    #[test]
    fn a_retired_connection_hears_the_acknowledgement_its_farewell_waits_on() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, mut peer, shared) = live_connection(&listener, tx);
        let mut writer = DatagramWriter::new(Arc::clone(&listener), cid, Arc::clone(&shared));
        let farewell = ServerMessage::Exit { code: 0 }
            .encode(Version::LOCAL)
            .expect("a farewell encodes");
        // Filled with the farewell frame itself, so the window shuts for it too.
        while writer
            .write_frames(&[IoSlice::new(&farewell)], FrameSet::default())
            .is_ok()
        {}
        writer
            .write_frames(&[IoSlice::new(&farewell)], FrameSet::default())
            .expect_err("the window is shut for the farewell too");
        drop(writer);

        let sent = peer.drain().len();
        assert!(sent > 0, "nothing reached the peer to acknowledge");
        let mut ack = Vec::new();
        peer.endpoint
            .poll_transmit(Instant::now() + Duration::from_millis(100), &mut ack)
            .expect("the peer owes an acknowledgement for what arrived");
        listener.overhear(
            arrival(cid, &peer),
            &departing(listener.route(cid)),
            &mut ack,
            &mut Scratch::default(),
        );

        let mut outbound = Outbound::default();
        listener.tick(Instant::now(), &mut outbound, &mut Vec::new());
        outbound.flush(&listener.socket);

        assert!(
            peer.drain()
                .iter()
                .any(|message| matches!(message, ServerMessage::Exit { code: 0 })),
            "the session's last word never left a window nothing could reopen"
        );
    }

    /// `parting` is keyed by connection id on a daemon that never exits: nothing a
    /// peer sends puts an entry here, and the window is what takes it back out.
    #[test]
    fn a_parting_connection_is_forgotten_when_its_farewell_window_closes() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, _peer, _shared) = parting_connection(&listener, tx);
        assert_eq!(
            listener.read().parting.len(),
            1,
            "a connection that retired owing its last word was not held for it"
        );

        let mut outbound = Outbound::default();
        listener.tick(
            Instant::now() + FAREWELL_WINDOW,
            &mut outbound,
            &mut Vec::new(),
        );

        assert!(
            listener.read().parting.is_empty(),
            "a wire held for a message nobody is waiting for any more"
        );
        assert!(
            matches!(listener.route(cid), Route::Unknown),
            "the connection is still addressable after its window closed"
        );
    }

    /// A parting connection is a connection: its acknowledgement, loss timer and MTU
    /// search run on the same clock, so the tick must sleep on its deadline too.
    #[test]
    fn the_tick_sleeps_on_a_parting_endpoints_own_deadline() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, mut peer, shared) = parting_connection(&listener, tx);
        let mut arriving = keystroke(&mut peer);
        listener.overhear(
            arrival(cid, &peer),
            &departing(listener.route(cid)),
            &mut arriving,
            &mut Scratch::default(),
        );
        let owed = wire(&shared)
            .endpoint
            .poll_deadline()
            .expect("a farewell in flight and a keystroke heard leave timers running");

        // Still ahead, so [`POLL_INTERVAL`] cannot be the soonest this tick names.
        let now = owed
            .checked_sub(POLL_INTERVAL / 2)
            .expect("a deadline the test just took a clock reading before");
        let deadline = listener.tick(now, &mut Outbound::default(), &mut Vec::new());

        assert_eq!(
            deadline, owed,
            "the tick slept past the deadline a parting endpoint named"
        );
    }

    /// An unvalidated address may cost a retiring connection no more than its path
    /// is wide, and the refusal must land before the replay window spends a number.
    #[test]
    fn a_retiring_connection_refuses_a_stranger_a_datagram_wider_than_its_path() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, mut peer, shared) = parting_connection(&listener, tx);
        // The floor of every published budget: the tightest bound it could have
        // had, and the route reads it as the width it refuses a stranger past.
        wire(&shared).limit.publish(0);
        let departing = departing(listener.route(cid));

        let now = Instant::now();
        let mut wide = widest_datagram(&mut peer);
        assert!(
            wide.len() > departing.width,
            "the fixture built a datagram the narrowed path still carries"
        );
        let quiet = wire(&shared).endpoint.poll_deadline();
        listener.overhear(
            Arrival {
                cid,
                from: SocketAddr::from((Ipv6Addr::LOCALHOST, 9)),
                at: now,
            },
            &departing,
            &mut wide,
            &mut Scratch::default(),
        );
        assert_eq!(
            wire(&shared).endpoint.poll_deadline(),
            quiet,
            "an address the connection never validated was opened anyway"
        );

        listener.overhear(
            Arrival {
                cid,
                from: peer.address,
                at: now,
            },
            &departing,
            &mut wide,
            &mut Scratch::default(),
        );

        assert_ne!(
            wire(&shared).endpoint.poll_deadline(),
            quiet,
            "the peer's own datagram was refused as a replay: the stranger's copy had already spent its packet number"
        );
    }

    /// The lingering close sends to an address the connection remembers, which is
    /// exactly where an anti-amplification rule gets bypassed by accident.
    #[test]
    fn a_farewell_waits_for_the_budget_its_peer_earns() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, mut peer, shared) = claimed_connection(&listener, tx);
        let mut writer = DatagramWriter::new(Arc::clone(&listener), cid, Arc::clone(&shared));
        let farewell = ServerMessage::Exit { code: 0 }
            .encode(Version::LOCAL)
            .expect("a farewell encodes");
        writer
            .write_frames(&[IoSlice::new(&farewell)], FrameSet::default())
            .expect_err("an address that has sent nothing is owed nothing");
        drop(writer);

        // One reading for the whole test: draining an empty socket costs its read
        // timeout, which would put the tick past the spacing it is measuring.
        let now = Instant::now();
        let mut outbound = Outbound::default();
        listener.tick(now, &mut outbound, &mut Vec::new());
        outbound.flush(&listener.socket);
        assert!(
            peer.nonces().is_empty(),
            "a farewell was aimed at an address that had sent nothing"
        );

        // A full datagram is what earns the challenge, the probe and the farewell.
        let mut arriving = widest_datagram(&mut peer);
        listener.overhear(
            Arrival {
                cid,
                from: peer.address,
                at: now,
            },
            &departing(listener.route(cid)),
            &mut arriving,
            &mut Scratch::default(),
        );
        // A copy the window refused is owed again a spacing later, not at once.
        listener.tick(now + FAREWELL_SPACING, &mut outbound, &mut Vec::new());
        outbound.flush(&listener.socket);

        assert!(
            peer.drain()
                .iter()
                .any(|message| matches!(message, ServerMessage::Exit { code: 0 })),
            "the farewell never left once its peer had paid for it"
        );
    }

    /// The demux is one acquisition, and a read: a second reader must not block it.
    #[test]
    fn one_read_of_the_map_routes_a_datagram() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, _rx) = mailbox();
        let (cid, _peer, _wire) = live_connection(&listener, tx);
        let held = listener.read();

        let live = attached(listener.route(cid));

        assert_eq!(live.id, AttachmentId(1));
        drop(held);
        let offer = listener.offer().expect("an offer");
        assert!(matches!(
            listener.route(ConnectionId::from_bytes(offer.cid)),
            Route::Pending
        ));
        assert!(matches!(
            listener.route(ConnectionId::from_bytes([0xAB; 8])),
            Route::Unknown
        ));
    }

    #[test]
    fn an_unadmitted_source_is_capped_and_the_table_is_not() {
        let mut limiter = Limiter::default();
        let mut now = Instant::now();
        let source = IpAddr::from(Ipv6Addr::LOCALHOST);
        for spent in 0..ADMIT_BURST {
            assert!(
                limiter.admits(source, now),
                "the burst was refused after {spent}"
            );
        }
        assert!(!limiter.admits(source, now), "the burst had no bottom");
        assert!(
            limiter.admits(source, now + ADMIT_REFILL),
            "the bucket never refilled"
        );

        // Paced so the daemon-wide bucket keeps up; the aggregate is the test below.
        for host in 0..u16::try_from(ADMIT_SOURCES).expect("a small table") * 4 {
            now += ADMIT_GLOBAL_REFILL;
            let flood = IpAddr::from(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, host));
            assert!(limiter.admits(flood, now), "a source it has never seen");
        }
        assert!(
            limiter.sources.len() <= ADMIT_SOURCES,
            "the limiter is the memory exhaustion it was added to prevent"
        );
    }

    /// The per-source bucket is keyed on an unverified address, so alone it bounds
    /// nothing: the daemon-wide bucket is what makes the aggregate bound true.
    #[test]
    fn a_flood_of_invented_sources_is_bounded_in_aggregate() {
        let mut limiter = Limiter::default();
        let now = Instant::now();
        let mut admitted = 0u32;
        for host in 0..u16::MAX {
            let spoofed = IpAddr::from(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, host));
            if limiter.admits(spoofed, now) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, ADMIT_GLOBAL_BURST);
    }

    /// A live connection is delivered on a route that never consults the limiter.
    #[test]
    fn a_live_connection_is_not_rate_limited() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let (tx, rx) = mailbox();
        let (cid, mut peer, _wire) = live_connection(&listener, tx);
        let mut limiter = Limiter::default();
        let source = peer.address.ip();
        while limiter.admits(source, Instant::now()) {}

        let mut delivered = 0;
        for _ in 0..ADMIT_BURST * 2 {
            let mut datagram = keystroke(&mut peer);
            match listener.route(cid) {
                Route::Live(live) => {
                    listener.deliver(
                        arrival(cid, &peer),
                        &live,
                        &mut datagram,
                        &mut Scratch::default(),
                    );
                    delivered += 1;
                }
                Route::Parting(_) | Route::Pending | Route::Unknown => {}
            }
        }

        assert_eq!(delivered, ADMIT_BURST * 2);
        assert!(
            rx.recv_timeout(Duration::ZERO).is_ok(),
            "a limiter that had run dry swallowed a session's keystrokes"
        );
    }

    /// An offer for a socket nobody serves costs every attachment its probe budget.
    #[test]
    fn a_panicking_thread_body_stops_the_offers() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        assert!(listener.offer().is_some());

        // The hook is process-wide: swapping it under a test that installed
        // its own would swallow that test's panic.
        let silenced = panic_hook();
        let quiet = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let died = panic::catch_unwind(AssertUnwindSafe(|| {
            let _serving = Serving::new(&listener, "receive");
            panic!("the thread body died");
        }));
        panic::set_hook(quiet);
        drop(silenced);

        assert!(died.is_err(), "the test did not panic");
        assert!(
            listener.offer().is_none(),
            "a panicked reader kept minting paths nobody would answer"
        );
    }

    /// An offer is spent by a resume, not by the first datagram to arrive.
    #[test]
    fn an_offer_survives_a_first_datagram_that_is_not_a_resume() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let daemon = Arc::new(DaemonState::default());
        let offer = listener.offer().expect("an offer");
        let cid = ConnectionId::from_bytes(offer.cid);
        let mut peer = Peer::new(cid, offer.secret);
        let frame = ClientMessage::Pong {
            token: 1,
            consumed: ByteOff::zero(),
        }
        .encode(Version::LOCAL)
        .expect("a pong encodes");
        let mut datagram = sealed(&mut peer, &frame);

        listener.admit(
            &daemon,
            arrival(cid, &peer),
            &mut datagram,
            &mut Scratch::default(),
        );

        assert!(
            listener.read().pending.contains_key(&cid),
            "one stray datagram burned the client's datagram path"
        );
    }

    /// The other half, and the whole admission path: the offer is spent exactly then.
    #[test]
    fn a_resume_on_an_offer_becomes_an_attachment() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let daemon = Arc::new(DaemonState::default());
        let (_ticket, session_id, capability) = persisted_ticket();
        let (tx, rx) = mailbox();
        registry(&daemon)
            .sessions
            .insert(session_id, detached_handle(tx));
        let offer = listener.offer().expect("an offer");
        let cid = ConnectionId::from_bytes(offer.cid);
        let mut peer = Peer::new(cid, offer.secret);
        let frame = resume(session_id, capability, client(7))
            .encode(Version::LOCAL)
            .expect("a resume encodes");
        let mut datagram = sealed(&mut peer, &frame);

        listener.admit(
            &daemon,
            arrival(cid, &peer),
            &mut datagram,
            &mut Scratch::default(),
        );

        assert!(
            listener.read().live.contains_key(&cid),
            "a resume that authenticated never became a connection"
        );
        assert!(
            !listener.read().pending.contains_key(&cid),
            "the offer outlived the resume that spent it"
        );
        assert!(
            matches!(
                rx.recv_timeout(Duration::ZERO),
                Ok(ActorEvent::Attach { .. })
            ),
            "the session was never told it had an attachment"
        );
    }

    /// Pruned by the clock rather than by the next offer, which may never be minted.
    #[test]
    fn an_expired_offer_is_pruned_without_a_second_one() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let offer = listener.offer().expect("an offer");
        let cid = ConnectionId::from_bytes(offer.cid);
        let stale = Instant::now()
            .checked_sub(OFFER_LIFETIME)
            .expect("a clock older than one offer");
        listener
            .write()
            .pending
            .get_mut(&cid)
            .expect("the offer is pending")
            .minted = stale;

        // What the transmit tick does with `pending`, on the clock it does it.
        let now = Instant::now();
        listener
            .write()
            .pending
            .retain(|_, offer| offer.minted + OFFER_LIFETIME > now);

        assert!(!listener.read().pending.contains_key(&cid));
    }

    /// `answer` seals a real datagram under the offer's keys, so the offer must be
    /// gone by then: a retry would rebuild an endpoint over a spent keystream.
    #[test]
    fn a_reject_spends_the_offer_it_answered() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let daemon = Arc::new(DaemonState::default());
        // Issued and deliberately not persisted, so `load_ticket` fails.
        let ticket = sessions::SessionTicket::issue().expect("a session ticket");
        let offer = listener.offer().expect("an offer");
        let cid = ConnectionId::from_bytes(offer.cid);
        let mut peer = Peer::new(cid, offer.secret);
        let frame = resume(
            ticket.session_id,
            Capability::from_bytes(ticket.capability),
            client(9),
        )
        .encode(Version::LOCAL)
        .expect("a resume encodes");
        let mut datagram = sealed(&mut peer, &frame);
        let mut retry = datagram.clone();

        listener.admit(
            &daemon,
            arrival(cid, &peer),
            &mut datagram,
            &mut Scratch::default(),
        );
        assert!(
            !listener.read().pending.contains_key(&cid),
            "an offer that sealed a reject under its keys is still spendable"
        );
        assert!(matches!(listener.route(cid), Route::Unknown));

        // What the client's probe loop does next: the identical resume again.
        listener.admit(
            &daemon,
            arrival(cid, &peer),
            &mut retry,
            &mut Scratch::default(),
        );

        let nonces = peer.nonces();
        let mut unique = nonces.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            nonces.len(),
            "two datagrams under one root secret at one (epoch, number) is one keystream twice"
        );
        assert_eq!(nonces.len(), 1, "the reject, and nothing after it");
    }

    /// The budget the actor reads follows the path and never drops below what the
    /// protocol guarantees.
    #[test]
    fn the_published_budget_follows_the_path() {
        let limit = PayloadLimit::fixed(MIN_DATAGRAM_FRAME);
        assert_eq!(limit.get(), MIN_DATAGRAM_FRAME);
        for payload in [
            BASE_DATAGRAM - HEADER_BYTES - TAG_BYTES,
            MAX_DATAGRAM - HEADER_BYTES - TAG_BYTES,
        ] {
            limit.publish(payload);
            assert_eq!(limit.get(), frame_budget(payload));
        }
        limit.publish(0);
        assert_eq!(
            limit.get(),
            MIN_DATAGRAM_FRAME,
            "a budget below the protocol's floor is one no message can be cut to"
        );
    }

    /// Anything that names a sooner deadline wakes the sleeping transmit thread.
    #[test]
    fn a_sooner_deadline_wakes_the_transmit_thread() {
        let clock = Arc::new(Clock::default());
        let waking = Arc::clone(&clock);
        let started = Instant::now();
        let sleeper = thread::spawn(move || {
            waking.sleep_until(started + Duration::from_secs(30));
            Instant::now()
        });
        // The sleeper has to be inside `wait_timeout` for the notify to end it.
        thread::sleep(Duration::from_millis(20));
        clock.advance(Instant::now());

        let woke = sleeper.join().expect("the sleeper returns");
        assert!(
            woke.saturating_duration_since(started) < Duration::from_secs(1),
            "the tick slept through a deadline it was told about"
        );
    }

    /// A number missing from this line is one nothing else in this daemon asks for.
    #[test]
    fn a_transport_report_carries_every_number_the_endpoint_answers_with() {
        let measured = Stats {
            cwnd: 12_000,
            bytes_in_flight: 3_400,
            srtt: Some(Duration::from_millis(42)),
            rttvar: Duration::from_millis(7),
            plpmtu: 1_200,
            lost: 5,
            spurious: 2,
        };
        let line = transport(&measured);
        for number in ["12000", "3400", "42ms", "7ms", "1200", "5", "2"] {
            assert!(line.contains(number), "{number} is missing from {line:?}");
        }

        // A link with no round trip yet says so rather than printing a LAN-like zero.
        assert!(
            transport(&Stats {
                srtt: None,
                ..measured
            })
            .contains("srtt -"),
            "an unmeasured round trip is reported as a measurement"
        );
    }

    /// The whole admission path over a real socket, end to end.
    #[test]
    fn a_resume_over_the_datagram_path_reaches_the_session() {
        let listener = dgram::DatagramListener::bind().expect("a datagram socket");
        let daemon = Arc::new(DaemonState {
            sessions: Mutex::default(),
            connections: AtomicUsize::new(0),
            forwards: AtomicUsize::new(0),
            dgram: Some(Arc::clone(&listener)),
        });
        let (ticket, session_id, capability) = persisted_ticket();
        let handle = daemon_session(&daemon, ticket, &[]);
        listener.serve(&daemon);
        let offer = datagram_offer(&daemon).expect("a daemon with a socket offers a path");

        let address = SocketAddr::from((Ipv6Addr::LOCALHOST, offer.port));
        let mut peer = Peer::dialling(ConnectionId::from_bytes(offer.cid), offer.secret, address);
        let frame = resume(session_id, capability, client(7))
            .encode(Version::LOCAL)
            .expect("encode the resume");
        let datagram = sealed(&mut peer, &frame);
        peer.socket
            .send_to(&datagram, address)
            .expect("send the resume");

        let deadline = Instant::now() + Duration::from_secs(10);
        let greeted = loop {
            if let Some(greeted) = peer.drain().iter().find_map(|message| match message {
                ServerMessage::Hello { session_id, .. } => Some(*session_id),
                _ => None,
            }) {
                break greeted;
            }
            assert!(
                Instant::now() < deadline,
                "the session never answered the resume"
            );
        };
        assert_eq!(
            greeted, session_id,
            "the datagram attachment was given another session"
        );
        assert!(
            attachments_settle(&handle, 1),
            "the resume never became an attachment"
        );
        handle.tx.send(kill()).expect("close test PTY");
    }

    /// The pool exists to recycle a steady state's buffers, not to remember the
    /// worst tick the daemon ever had. Every slot holds `MAX_DATAGRAM`, so a
    /// peak that is never given back is resident memory nothing charges for.
    #[test]
    fn a_burst_of_datagrams_does_not_pin_its_peak() {
        let listener = DatagramListener::bind().expect("a datagram socket");
        let mut outbound = Outbound::default();
        let peer = SocketAddr::from((Ipv6Addr::LOCALHOST, 9));
        let burst = OUTBOUND_SLOTS * 4;
        for _ in 0..burst {
            assert!(
                outbound.seal(|out| {
                    out.extend_from_slice(b"a datagram");
                    Some(peer)
                }),
                "the pool refused to grow for the burst it is measured against"
            );
        }
        assert_eq!(
            outbound.slots.len(),
            burst,
            "the burst was meant to take the pool past its bound"
        );

        outbound.flush(&listener.socket);
        assert_eq!(outbound.filled, 0);
        assert_eq!(
            outbound.slots.len(),
            OUTBOUND_SLOTS,
            "a burst's high-water mark outlived the tick that caused it"
        );

        // What the bound keeps is still a pool: a steady state reseals into the
        // buffers it already has rather than allocating a slot per datagram.
        for _ in 0..OUTBOUND_SLOTS {
            assert!(outbound.seal(|out| {
                out.extend_from_slice(b"a datagram");
                Some(peer)
            }));
        }
        assert_eq!(
            outbound.slots.len(),
            OUTBOUND_SLOTS,
            "the retained slots were not reused"
        );
    }
}
