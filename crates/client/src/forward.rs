#![forbid(unsafe_code)]

//! `-L`: local listeners whose connections the session carries. Lock order
//! everywhere here: the table, then a connection's buffer or its credit, never
//! the reverse. Nothing in this module blocks on a peer.

use crate::ClientError;
use crate::outbound::{ClientWriter, FrameSink};
use crate::terminal::{Stake, staked};
use braid_forward::Stream;
use braid_proto::SackRuns;
use braid_proto::{
    ByteOff, ClientMessage, ForwardResetReason, ForwardTarget, MAX_FORWARD_CHUNK, MAX_FORWARD_HOST,
    MAX_FORWARDS, StreamId,
};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Bytes waiting for one local socket, deliberately far below
/// [`braid_forward::FORWARD_WINDOW`]: what the pump cannot hand over stays
/// unconsumed, closing the advertised window that paces the far end.
const LOCAL_BACKLOG: usize = 64 * 1024;

/// Stream ids remembered after they close, so a peer whose segments are still
/// on the wire is answered rather than left holding the socket open.
const CLOSED_RING: usize = 32;

/// Delay before a refused frame is offered again; retrying at once spins.
const REFUSED_RETRY: Duration = Duration::from_millis(10);

/// Teardown knock deadline; only a stalled machine ever spends it.
const KNOCK: Duration = Duration::from_millis(250);

/// Sealing on the datagram path builds a deflate compressor on the stack —
/// `wire::CODEC_STACK` — and a stack overflow is a `SIGSEGV` no hook contains.
const SEALING_STACK: usize = 1024 * 1024;

/// The default is 8 MiB of address space apiece, and each connection runs two.
const MOVER_STACK: usize = 256 * 1024;

const _: () = assert!(SEALING_STACK > braid_proto::wire::CODEC_STACK + 64 * 1024);

const PUMP_THREAD: &str = "brd-forward";
const ACCEPT_THREAD: &str = "brd-forward-accept";
const READ_THREAD: &str = "brd-forward-read";
const WRITE_THREAD: &str = "brd-forward-write";

/// One value per shape: "invalid forward specification" names none of them.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ForwardSpecError {
    #[error("expected [bind_address:]port:host:hostport")]
    Shape,
    #[error("an IPv6 literal needs brackets: [::1]:port:host:hostport")]
    Brackets,
    #[error("listen port is not a port number")]
    ListenPort,
    #[error("bind address is not an IP address, 'localhost' or '*'")]
    BindAddress,
    #[error("target host is empty")]
    TargetHost,
    #[error("target host is longer than {} bytes", MAX_FORWARD_HOST)]
    TargetHostLength,
    #[error("target port is not a port number")]
    TargetPort,
    /// Port zero asks the kernel to choose; this client is in raw mode with no
    /// channel to report the number on, so it refuses rather than binds.
    #[error("port 0 lets the kernel choose, and nothing here can report what it chose")]
    Ephemeral,
}

/// An unqualified `-L` listens on loopback, as `ssh` does without `GatewayPorts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    pub bind: IpAddr,
    pub port: u16,
    pub target: ForwardTarget,
}

/// Fields the grammar has room for.
const FIELDS: usize = 4;

impl ForwardSpec {
    /// `ssh`'s own `[bind_address:]port:host:hostport`. `*` and an empty bind
    /// address mean every address; `localhost` is spelled out, not resolved.
    pub fn parse(spec: &str) -> Result<Self, ForwardSpecError> {
        let fields = split_fields(spec)?;
        let (bind, port, host, hostport) = match fields.as_slice() {
            [port, host, hostport] => (None, *port, *host, *hostport),
            [bind, port, host, hostport] => (Some(*bind), *port, *host, *hostport),
            _ => return Err(ForwardSpecError::Shape),
        };
        let bind = match bind {
            None | Some("localhost") => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some("" | "*") => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Some(address) => address.parse().map_err(|_| ForwardSpecError::BindAddress)?,
        };
        let port: u16 = port.parse().map_err(|_| ForwardSpecError::ListenPort)?;
        let target_port: u16 = hostport.parse().map_err(|_| ForwardSpecError::TargetPort)?;
        if port == 0 || target_port == 0 {
            return Err(ForwardSpecError::Ephemeral);
        }
        if host.is_empty() {
            return Err(ForwardSpecError::TargetHost);
        }
        // The wire's host field is length-prefixed by a `u8`.
        if host.len() > MAX_FORWARD_HOST {
            return Err(ForwardSpecError::TargetHostLength);
        }
        Ok(Self {
            bind,
            port,
            target: ForwardTarget {
                host: host.to_owned(),
                port: target_port,
            },
        })
    }
}

/// Split on `:`, taking `[...]` whole: an IPv6 literal is mostly colons.
fn split_fields(spec: &str) -> Result<Vec<&str>, ForwardSpecError> {
    let mut fields = Vec::with_capacity(FIELDS);
    let mut rest = spec;
    loop {
        let (field, tail) = if let Some(inner) = rest.strip_prefix('[') {
            let (literal, after) = inner.split_once(']').ok_or(ForwardSpecError::Brackets)?;
            match after.strip_prefix(':') {
                Some(tail) => (literal, Some(tail)),
                None if after.is_empty() => (literal, None),
                // `[::1]22`: the literal ended, and no separator followed it.
                None => return Err(ForwardSpecError::Brackets),
            }
        } else {
            match rest.split_once(':') {
                Some((field, tail)) => (field, Some(tail)),
                None => (rest, None),
            }
        };
        fields.push(field);
        // Stopped at the grammar's width, so a spec of nothing but separators
        // does not become a vector of them.
        if fields.len() > FIELDS {
            return Err(ForwardSpecError::Shape);
        }
        match tail {
            Some(tail) => rest = tail,
            None => return Ok(fields),
        }
    }
}

/// Bound before the session opens — `ExitOnForwardFailure=yes`. Silently
/// running without a tunnel surfaces far later, as a different failure.
pub(crate) struct Listeners {
    bound: Vec<(TcpListener, ForwardTarget)>,
}

impl Listeners {
    pub(crate) fn bind(specs: &[ForwardSpec]) -> Result<Self, ClientError> {
        let mut bound = Vec::with_capacity(specs.len());
        for spec in specs {
            let address = SocketAddr::new(spec.bind, spec.port);
            let listener = TcpListener::bind(address).map_err(|error| {
                ClientError::Forward(format!("cannot listen on {address}: {error}"))
            })?;
            bound.push((listener, spec.target.clone()));
        }
        Ok(Self { bound })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bound.is_empty()
    }
}

/// One forwarded connection and the three threads it owns. Dropping this wakes
/// all three — shutdown, closed buffer, closed credit — and none are joined;
/// the entry's absence is what gives the [`MAX_FORWARDS`] slot back.
struct Conn {
    stream: Stream,
    /// The reader and the writer each hold a duplicate of their own.
    socket: TcpStream,
    writer: LocalWriter,
    credit: Arc<Credit>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        self.writer.close();
        self.credit.close();
    }
}

struct Table {
    live: HashMap<StreamId, Conn>,
    /// Never reused within a session: an id the far end still has a frame for
    /// must not come back naming a different connection.
    next: StreamId,
    closed: [Option<StreamId>; CLOSED_RING],
    closed_at: usize,
    /// Bounded like the ring it is fed from: one that waited out a whole ring
    /// describes a connection the peer has long since given up on.
    resets: VecDeque<(StreamId, ForwardResetReason)>,
    stopped: bool,
}

impl Table {
    fn remember_closed(&mut self, id: StreamId) {
        self.closed[self.closed_at] = Some(id);
        self.closed_at = (self.closed_at + 1) % CLOSED_RING;
    }

    fn was_closed(&self, id: StreamId) -> bool {
        self.closed.contains(&Some(id))
    }

    fn reset(&mut self, id: StreamId, reason: ForwardResetReason) {
        if self.resets.len() >= CLOSED_RING {
            self.resets.pop_front();
        }
        self.resets.push_back((id, reason));
    }

    /// `None` is a stream the far end already knows is gone: a reset is never
    /// answered with a reset, or two ends that disagree trade them forever.
    fn retire(&mut self, id: StreamId, reason: Option<ForwardResetReason>) {
        if self.live.remove(&id).is_none() {
            return;
        }
        self.remember_closed(id);
        if let Some(reason) = reason {
            self.reset(id, reason);
        }
    }
}

struct Shared<W> {
    table: Mutex<Table>,
    /// Wakes the pump, and always notified under `table`: a notification that
    /// races the pump into its wait stalls a forward until its own timer fires.
    wake: Condvar,
    writer: Arc<ClientWriter<W>>,
    /// Counted rather than printed: the session holds the terminal in raw
    /// mode, so this is reported once the terminal is its own again.
    refused: AtomicU32,
}

impl<W> Shared<W> {
    fn notify(&self) {
        if let Ok(_table) = self.table.lock() {
            self.wake.notify_one();
        }
    }

    fn stopped(&self) -> bool {
        self.table.lock().is_ok_and(|table| table.stopped)
    }

    fn stop(&self) -> u32 {
        if let Ok(mut table) = self.table.lock() {
            table.stopped = true;
            // Each `Conn` dropped here closes its socket and wakes its threads.
            table.live.clear();
            self.wake.notify_all();
        }
        self.refused.load(Ordering::Acquire)
    }

    /// Reports what the stream took and the room left, which is what the
    /// reader's next read is cut to — a count it cannot correct for itself.
    fn ingest(&self, id: StreamId, bytes: &[u8]) -> Option<(usize, usize)> {
        let Ok(mut table) = self.table.lock() else {
            return None;
        };
        let conn = table.live.get_mut(&id)?;
        let taken = conn.stream.write(bytes, Instant::now());
        let room = conn.stream.writable();
        self.wake.notify_one();
        Some((taken, room))
    }

    fn local_end(&self, id: StreamId) {
        let Ok(mut table) = self.table.lock() else {
            return;
        };
        if let Some(conn) = table.live.get_mut(&id) {
            conn.stream.finish();
        }
        self.wake.notify_one();
    }

    /// The local socket failed, which no retransmission repairs.
    fn local_failed(&self, id: StreamId) {
        let Ok(mut table) = self.table.lock() else {
            return;
        };
        table.retire(id, Some(ForwardResetReason::Closed));
        self.wake.notify_one();
    }
}

pub(crate) struct Forwards<W> {
    shared: Arc<Shared<W>>,
    /// So a teardown can knock: nothing else wakes a thread inside `accept`.
    doors: Vec<SocketAddr>,
}

impl<W: FrameSink + Send + Sync + 'static> Forwards<W> {
    /// Separate from [`Listeners::bind`] because the ports are taken before
    /// the session exists, and these threads need the writer it produced.
    pub(crate) fn start(
        listeners: Listeners,
        writer: &Arc<ClientWriter<W>>,
    ) -> Result<Self, ClientError> {
        let shared = Arc::new(Shared {
            table: Mutex::new(Table {
                live: HashMap::new(),
                next: StreamId::first(),
                closed: [None; CLOSED_RING],
                closed_at: 0,
                resets: VecDeque::new(),
                stopped: false,
            }),
            wake: Condvar::new(),
            writer: Arc::clone(writer),
            refused: AtomicU32::new(0),
        });
        // Built before the threads, so a failed spawn leaves through `Drop`.
        let mut forwards = Self {
            shared,
            doors: Vec::with_capacity(listeners.bound.len()),
        };
        let pumping = Arc::clone(&forwards.shared);
        thread::Builder::new()
            .name(PUMP_THREAD.into())
            .stack_size(SEALING_STACK)
            .spawn(staked(Stake::Tunnel, move || pump_loop(&pumping)))
            .map_err(|_| io::Error::other("forward pump thread failed"))?;
        for (listener, target) in listeners.bound {
            forwards.doors.push(listener.local_addr()?);
            let accepting = Arc::clone(&forwards.shared);
            thread::Builder::new()
                .name(ACCEPT_THREAD.into())
                .stack_size(SEALING_STACK)
                .spawn(staked(Stake::Tunnel, move || {
                    accept_loop(&accepting, &listener, &target);
                }))
                .map_err(|_| io::Error::other("forward accept thread failed"))?;
        }
        Ok(forwards)
    }

    /// Runs on the session loop, which also holds the display lock: a copy into
    /// the receive buffer and a notification. The socket is the pump's business.
    pub(crate) fn on_data(&self, stream: StreamId, off: ByteOff, fin: bool, bytes: &[u8]) {
        let Ok(mut table) = self.shared.table.lock() else {
            return;
        };
        let placed = table
            .live
            .get_mut(&stream)
            .map(|conn| conn.stream.on_data(off.get(), fin, bytes));
        match placed {
            // Self-contradiction; no retransmission repairs one.
            Some(Err(_)) => table.retire(stream, Some(ForwardResetReason::Internal)),
            // Silence would leave the daemon holding a socket for it.
            None if table.was_closed(stream) => table.reset(stream, ForwardResetReason::Closed),
            // Placed, or an id whose close has aged out of the ring.
            Some(Ok(())) | None => {}
        }
        self.shared.wake.notify_one();
    }

    pub(crate) fn on_ack(&self, stream: StreamId, off: ByteOff, window: u32, held: &SackRuns) {
        let Ok(mut table) = self.shared.table.lock() else {
            return;
        };
        let known = table.live.get_mut(&stream).map(|conn| {
            conn.stream
                .on_ack(off.get(), window, held, Instant::now())
                .is_ok()
        });
        match known {
            // The daemon claims bytes this side never sent.
            Some(false) => table.reset(stream, ForwardResetReason::Internal),
            None if table.was_closed(stream) => table.reset(stream, ForwardResetReason::Closed),
            _ => {}
        }
        self.shared.wake.notify_one();
    }

    /// Never answered with a reset of this end's own.
    pub(crate) fn on_reset(&self, stream: StreamId) {
        let Ok(mut table) = self.shared.table.lock() else {
            return;
        };
        table.retire(stream, None);
        self.shared.wake.notify_one();
    }

    /// The pump sleeps with no deadline while there is no link, so this is the
    /// one event it cannot observe; without it a tunnel resumes on its next byte.
    pub(crate) fn link_restored(&self) {
        self.shared.notify();
    }
}

impl<W> Drop for Forwards<W> {
    fn drop(&mut self) {
        let refused = self.shared.stop();
        for door in &self.doors {
            // No flag reaches a thread inside `accept`: one connection to our
            // own listener returns it to the loop, where the flag is read.
            let _ = TcpStream::connect_timeout(door, KNOCK);
        }
        if refused > 0 {
            eprintln!(
                "[brd] {refused} forwarded connection(s) refused: {MAX_FORWARDS} at once is the limit"
            );
        }
    }
}

fn accept_loop<W: FrameSink + Send + Sync + 'static>(
    shared: &Arc<Shared<W>>,
    listener: &TcpListener,
    target: &ForwardTarget,
) {
    loop {
        let Ok((socket, _)) = listener.accept() else {
            return;
        };
        if shared.stopped() {
            return;
        }
        open(shared, socket, target);
    }
}

/// The table lock is held across both spawns on purpose: the capacity check
/// and the id are one decision, and two listeners must not both take the slot.
fn open<W: FrameSink + Send + Sync + 'static>(
    shared: &Arc<Shared<W>>,
    socket: TcpStream,
    target: &ForwardTarget,
) {
    // Nagle would hold a keystroke-sized frame for 40 ms waiting for company.
    let _ = socket.set_nodelay(true);
    let Ok(mut table) = shared.table.lock() else {
        return;
    };
    // Ids are never reused, so the last one ends this session's forwards.
    if table.stopped || table.live.len() >= MAX_FORWARDS || table.next.get() == u32::MAX {
        // A connection nothing will serve must fail like a refused `connect`,
        // not hang in the backlog looking established.
        shared.refused.fetch_add(1, Ordering::Release);
        return;
    }
    let (Ok(reading), Ok(writing)) = (socket.try_clone(), socket.try_clone()) else {
        return;
    };
    let id = table.next;
    let credit = Arc::new(Credit::default());
    let writer = LocalWriter::default();
    let reader_shared = Arc::clone(shared);
    let reader_credit = Arc::clone(&credit);
    if thread::Builder::new()
        .name(READ_THREAD.into())
        .stack_size(MOVER_STACK)
        .spawn(staked(Stake::Tunnel, move || {
            read_loop(&reader_shared, id, &reader_credit, reading);
        }))
        .is_err()
    {
        return;
    }
    let writer_shared = Arc::clone(shared);
    let writer_handle = writer.clone();
    if thread::Builder::new()
        .name(WRITE_THREAD.into())
        .stack_size(MOVER_STACK)
        .spawn(staked(Stake::Tunnel, move || {
            write_loop(&writer_shared, &writer_handle, writing);
        }))
        .is_err()
    {
        // No entry exists whose `Drop` would wake the reader off its credit.
        credit.close();
        return;
    }
    table.next = id.next();
    table.live.insert(
        id,
        Conn {
            stream: Stream::new(),
            socket,
            writer,
            credit,
        },
    );
    // A journal with no room is a forward that would never open; its threads
    // leave with the entry.
    if shared.writer.forward_open(id, target.clone()).is_err() {
        table.retire(id, None);
        return;
    }
    shared.wake.notify_one();
}

/// Local socket to stream. The credit keeps this from outrunning the send
/// buffer, so a stalled tunnel is backpressure rather than memory here.
fn read_loop<W: FrameSink>(
    shared: &Shared<W>,
    id: StreamId,
    credit: &Credit,
    mut socket: TcpStream,
) {
    // One wire segment: reading more than one frame can carry moves the wait.
    let mut buffer = vec![0_u8; MAX_FORWARD_CHUNK];
    loop {
        let allowed = credit.take(buffer.len());
        if allowed == 0 {
            return;
        }
        let read = match socket.read(&mut buffer[..allowed]) {
            Ok(0) => {
                shared.local_end(id);
                return;
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                shared.local_failed(id);
                return;
            }
        };
        let mut moved = 0;
        while moved < read {
            let Some((taken, room)) = shared.ingest(id, &buffer[moved..read]) else {
                return;
            };
            moved += taken;
            // Authoritative, and why a partial write cannot spin: a stream
            // that took nothing reports no room, so the next `take` waits.
            credit.grant(room);
            if moved < read && credit.take(read - moved) == 0 {
                return;
            }
        }
    }
}

/// Its own thread, and a `write` that refuses rather than waits.
fn write_loop<W: FrameSink>(shared: &Shared<W>, writer: &LocalWriter, mut socket: TcpStream) {
    let mut batch = Vec::new();
    'move_bytes: loop {
        let Ok(mut buffer) = writer.buffer.lock() else {
            return;
        };
        while buffer.bytes.is_empty() {
            if buffer.closed {
                break 'move_bytes;
            }
            if buffer.ended {
                drop(buffer);
                // The local application sees the close it would have seen with
                // no tunnel in the way.
                let _ = socket.shutdown(Shutdown::Write);
                break 'move_bytes;
            }
            let Ok(next) = writer.ready.wait(buffer) else {
                return;
            };
            buffer = next;
        }
        std::mem::swap(&mut batch, &mut buffer.bytes);
        buffer.bytes.clear();
        drop(buffer);
        if socket.write_all(&batch).is_err() {
            if let Ok(mut buffer) = writer.buffer.lock() {
                buffer.failed = true;
            }
            break 'move_bytes;
        }
        batch.clear();
        // The pump may hold bytes this drain made room for, and has no clock.
        shared.notify();
    }
    // On the way out too, including failure: the pump retires this stream on
    // either and must never wait for a thread that has left.
    shared.notify();
}

/// The one thread that touches every stream, so the table lock is the only
/// synchronisation the streams themselves need.
fn pump_loop<W: FrameSink>(shared: &Shared<W>) {
    // Reused across cycles: one cycle per arriving frame, at copy speed.
    let mut ids = Vec::new();
    let mut retire = Vec::new();
    let mut payload = Vec::new();
    let Ok(mut table) = shared.table.lock() else {
        return;
    };
    loop {
        if table.stopped {
            return;
        }
        let wait = pump(shared, &mut table, &mut ids, &mut retire, &mut payload);
        let waited = match wait {
            Some(wait) => shared
                .wake
                .wait_timeout(table, wait)
                .map(|(guard, _)| guard)
                .map_err(drop),
            // Nothing is owed on a clock, and every event notifies under this
            // lock.
            None => shared.wake.wait(table).map_err(drop),
        };
        let Ok(next) = waited else {
            return;
        };
        table = next;
    }
}

/// One pass over every stream, reporting when the next one is owed.
fn pump<W: FrameSink>(
    shared: &Shared<W>,
    table: &mut Table,
    ids: &mut Vec<StreamId>,
    retire: &mut Vec<(StreamId, Option<ForwardResetReason>)>,
    payload: &mut Vec<u8>,
) -> Option<Duration> {
    let now = Instant::now();
    // `None` is a session with no link; the stream owes the bytes either way.
    let budget = shared.writer.forward_chunk().ok().flatten();
    let mut refused = false;
    let mut wait: Option<Duration> = None;

    while let Some(&(stream, reason)) = table.resets.front() {
        let message = ClientMessage::ForwardReset { stream, reason };
        if budget.is_none() || !shared.writer.forward_frame(&message).unwrap_or(false) {
            refused = budget.is_some();
            break;
        }
        table.resets.pop_front();
    }

    ids.clear();
    ids.extend(table.live.keys().copied());
    retire.clear();
    for id in ids.iter().copied() {
        let Some(conn) = table.live.get_mut(&id) else {
            continue;
        };
        // Only what the local buffer took is consumed: the rest stays in the
        // receive buffer, closing the window that paces the far end.
        let (front, back) = conn.stream.readable();
        let mut moved = conn.writer.write(front);
        if moved == front.len() {
            moved += conn.writer.write(back);
        }
        conn.stream.consume(moved);
        if conn.writer.failed() {
            retire.push((id, Some(ForwardResetReason::Closed)));
            continue;
        }
        let (front, back) = conn.stream.readable();
        // The end only once every byte before it has been handed over: an end
        // delivered early shuts a socket over data still in hand.
        if conn.stream.peer_finished() && front.is_empty() && back.is_empty() {
            conn.writer.finish();
        }
        conn.credit.grant(conn.stream.writable());

        if let Some(budget) = budget {
            // The ack goes before the data: it reopens the far end's window.
            // Not polled once the outbox has refused, because polling clears
            // the flag — the peer would only get the update on a retransmit.
            if !refused && let Some(ack) = conn.stream.poll_ack() {
                let message = ClientMessage::ForwardAck {
                    stream: id,
                    off: ByteOff::from_u64(ack.off),
                    window: ack.window,
                    held: ack.held,
                };
                refused |= !shared.writer.forward_frame(&message).unwrap_or(false);
            }
            while !refused {
                payload.clear();
                let Some(segment) = conn.stream.poll_transmit(now, budget, payload) else {
                    break;
                };
                let message = ClientMessage::ForwardData {
                    stream: id,
                    off: ByteOff::from_u64(segment.off),
                    fin: segment.fin,
                    bytes: std::mem::take(payload),
                };
                let accepted = shared.writer.forward_frame(&message).unwrap_or(false);
                // The payload buffer comes back out of the message it was lent
                // to; a fresh allocation per segment is what this cannot afford.
                if let ClientMessage::ForwardData { bytes, .. } = message {
                    *payload = bytes;
                }
                if !accepted {
                    refused = true;
                    break;
                }
                // Only now: a segment the sink refused is one the stream must
                // go on owing, which is what carries a tunnel over a disconnect.
                conn.stream.transmitted(segment, now);
            }
        }

        if conn.stream.is_done() && conn.writer.drained() {
            retire.push((id, None));
        } else if let Some(deadline) = budget.and(conn.stream.deadline(now)) {
            // An expired deadline reads as zero until `poll_transmit` clears
            // it, so waking with no link spins for as long as a laptop sleeps.
            wait = Some(wait.map_or(deadline, |soonest: Duration| soonest.min(deadline)));
        }
    }
    for (id, reason) in retire.drain(..) {
        table.retire(id, reason);
    }
    if refused {
        wait = Some(wait.map_or(REFUSED_RETRY, |soonest| soonest.min(REFUSED_RETRY)));
    }
    wait
}

/// A mutex and a condvar rather than a channel of bytes: the number handed
/// across is a ceiling, not a queue.
#[derive(Default)]
struct Credit {
    state: Mutex<CreditState>,
    ready: Condvar,
}

#[derive(Default)]
struct CreditState {
    allowed: usize,
    closed: bool,
}

impl Credit {
    /// Wait for room, and report at most `most` of it. Zero is gone.
    fn take(&self, most: usize) -> usize {
        let Ok(mut state) = self.state.lock() else {
            return 0;
        };
        while state.allowed == 0 {
            if state.closed {
                return 0;
            }
            let Ok(next) = self.ready.wait(state) else {
                return 0;
            };
            state = next;
        }
        if state.closed {
            return 0;
        }
        state.allowed.min(most)
    }

    fn grant(&self, allowed: usize) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.allowed = allowed;
        if allowed > 0 {
            self.ready.notify_one();
        }
    }

    fn close(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.closed = true;
        self.ready.notify_all();
    }
}

/// `write_all` blocks whenever the local application stops reading, and the
/// pump serves every other forward, so the write gets a thread of its own and
/// the pump gets a buffer that takes a prefix and refuses the rest.
#[derive(Clone, Default)]
struct LocalWriter {
    buffer: Arc<Mutex<WriteBuffer>>,
    ready: Arc<Condvar>,
}

#[derive(Default)]
struct WriteBuffer {
    bytes: Vec<u8>,
    /// The socket's write half follows once what is here has drained.
    ended: bool,
    /// The connection is gone; whatever is left goes with it.
    closed: bool,
    failed: bool,
}

impl LocalWriter {
    fn write(&self, bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            return 0;
        }
        let Ok(mut buffer) = self.buffer.lock() else {
            return 0;
        };
        if buffer.closed || buffer.failed {
            return 0;
        }
        let take = LOCAL_BACKLOG
            .saturating_sub(buffer.bytes.len())
            .min(bytes.len());
        if take == 0 {
            return 0;
        }
        buffer.bytes.extend_from_slice(&bytes[..take]);
        self.ready.notify_one();
        take
    }

    fn finish(&self) {
        let Ok(mut buffer) = self.buffer.lock() else {
            return;
        };
        buffer.ended = true;
        self.ready.notify_one();
    }

    fn close(&self) {
        let Ok(mut buffer) = self.buffer.lock() else {
            return;
        };
        buffer.closed = true;
        self.ready.notify_all();
    }

    fn failed(&self) -> bool {
        self.buffer.lock().is_ok_and(|buffer| buffer.failed)
    }

    /// The other half of what `Stream::is_done` answers: retiring drops the
    /// socket, and doing so over buffered bytes is loss at the last moment.
    fn drained(&self) -> bool {
        self.buffer
            .lock()
            .is_ok_and(|buffer| buffer.bytes.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::Carriage;
    use braid_proto::{CmdSeq, MAX_FRAME, Version, read_frame};
    use std::net::Ipv6Addr;

    fn spec(text: &str) -> ForwardSpec {
        ForwardSpec::parse(text).expect("a well formed forward")
    }

    /// An unqualified `-L` is a tunnel for this user, as `ssh` has it.
    #[test]
    fn a_well_formed_spec_resolves_its_bind_address_and_target() {
        let cases: [(&str, IpAddr, &str, u16); 8] = [
            (
                "8080:intranet:80",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "intranet",
                80,
            ),
            (
                "0.0.0.0:8080:intranet:80",
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                "intranet",
                80,
            ),
            (
                "*:8080:intranet:80",
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                "intranet",
                80,
            ),
            (
                ":8080:intranet:80",
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                "intranet",
                80,
            ),
            (
                "localhost:8080:intranet:80",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "intranet",
                80,
            ),
            (
                "[::1]:8080:intranet:80",
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                "intranet",
                80,
            ),
            (
                "8080:[2001:db8::1]:80",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "2001:db8::1",
                80,
            ),
            (
                "[::1]:8080:[::1]:22",
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                "::1",
                22,
            ),
        ];
        for (text, bind, host, port) in cases {
            let parsed = spec(text);
            assert_eq!(parsed.bind, bind, "`-L {text}` bind address");
            assert_eq!(parsed.port, 8080, "`-L {text}` listen port");
            assert_eq!(parsed.target.host, host, "`-L {text}` target host");
            assert_eq!(parsed.target.port, port, "`-L {text}` target port");
        }
    }

    /// Each shape names its own mistake.
    #[test]
    fn every_malformed_spec_is_refused_by_the_field_that_is_wrong() {
        use ForwardSpecError as Error;
        let cases: [(&str, Error); 12] = [
            ("", Error::Shape),
            ("8080", Error::Shape),
            ("8080:intranet", Error::Shape),
            ("a:b:c:d:e", Error::Shape),
            ("[::1:8080:intranet:80", Error::Brackets),
            ("[::1]8080:intranet:80", Error::Brackets),
            ("intranet:8080:intranet:80", Error::BindAddress),
            ("http:intranet:80", Error::ListenPort),
            ("99999:intranet:80", Error::ListenPort),
            ("8080:intranet:http", Error::TargetPort),
            ("8080::80", Error::TargetHost),
            ("0:intranet:80", Error::Ephemeral),
        ];
        for (spec, expected) in cases {
            assert_eq!(
                ForwardSpec::parse(spec),
                Err(expected),
                "`-L {spec}` was not refused as {expected:?}"
            );
        }
        let long = format!("8080:{}:80", "h".repeat(MAX_FORWARD_HOST + 1));
        assert_eq!(
            ForwardSpec::parse(&long),
            Err(Error::TargetHostLength),
            "a host the wire cannot carry must be refused where it is typed"
        );
    }

    /// The address is in the message because "Address already in use" alone
    /// sends a user looking at the wrong port.
    #[test]
    fn a_port_already_taken_is_refused_with_the_address_in_the_message() {
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port to hold");
        let taken = held.local_addr().expect("the held address");
        let refused = Listeners::bind(&[ForwardSpec {
            bind: taken.ip(),
            port: taken.port(),
            target: ForwardTarget {
                host: "intranet".into(),
                port: 80,
            },
        }])
        .err()
        .expect("a bound port cannot be bound twice");
        let message = refused.to_string();
        assert!(
            message.contains(&taken.to_string()),
            "the refusal must name the address: {message}"
        );
    }

    /// A frame sink that keeps whole frames, so a test can be the far end.
    /// Cloned rather than `Arc`-shared: the writer owns its sink.
    #[derive(Clone, Default)]
    struct Wire {
        frames: Arc<Mutex<Vec<u8>>>,
    }

    impl Wire {
        fn drain(&self) -> Vec<ClientMessage> {
            let bytes = {
                let mut queued = self.frames.lock().expect("the wire is not poisoned");
                std::mem::take(&mut *queued)
            };
            let mut input = &bytes[..];
            let mut messages = Vec::new();
            while !input.is_empty() {
                let payload = read_frame(&mut input, MAX_FRAME).expect("a framed message");
                messages.push(
                    ClientMessage::decode(&payload, Version::LOCAL).expect("a decodable message"),
                );
            }
            messages
        }
    }

    impl FrameSink for Wire {
        fn carriage(&self) -> Carriage {
            Carriage::Stream
        }

        fn send(&self, frame: Vec<u8>) -> bool {
            self.frames
                .lock()
                .map(|mut frames| frames.extend_from_slice(&frame))
                .is_ok()
        }
    }

    /// The daemon's half of one forward, driven by hand.
    struct FarEnd {
        stream: Stream,
        id: Option<StreamId>,
        target: Option<ForwardTarget>,
        received: Vec<u8>,
        /// Accepting only what fits is the far end's half of the backpressure.
        answer: Vec<u8>,
        answered: usize,
    }

    impl FarEnd {
        fn new() -> Self {
            Self {
                stream: Stream::new(),
                id: None,
                target: None,
                received: Vec::new(),
                answer: Vec::new(),
                answered: 0,
            }
        }

        /// Carry every frame each end has for the other, once.
        fn step(&mut self, wire: &Wire, forwards: &Forwards<Wire>) {
            let now = Instant::now();
            for message in wire.drain() {
                match message {
                    ClientMessage::ForwardOpen { stream, target, .. } => {
                        self.id = Some(stream);
                        self.target = Some(target);
                    }
                    ClientMessage::ForwardData {
                        off, fin, bytes, ..
                    } => {
                        self.stream
                            .on_data(off.get(), fin, &bytes)
                            .expect("the client does not contradict itself");
                    }
                    ClientMessage::ForwardAck { off, window, .. } => {
                        let _ = self.stream.on_ack(off.get(), window, &SackRuns::EMPTY, now);
                    }
                    _ => {}
                }
            }
            let (front, back) = self.stream.readable();
            let taken = front.len() + back.len();
            self.received.extend_from_slice(front);
            self.received.extend_from_slice(back);
            self.stream.consume(taken);
            let Some(id) = self.id else {
                return;
            };
            if let Some(ack) = self.stream.poll_ack() {
                forwards.on_ack(id, ByteOff::from_u64(ack.off), ack.window, &ack.held);
            }
            self.answered += self.stream.write(&self.answer[self.answered..], now);
            let mut payload = Vec::new();
            while let Some(segment) =
                self.stream
                    .poll_transmit(now, MAX_FORWARD_CHUNK, &mut payload)
            {
                forwards.on_data(
                    id,
                    ByteOff::from_u64(segment.off),
                    segment.fin,
                    &payload[..segment.len],
                );
                self.stream.transmitted(segment, now);
                payload.clear();
            }
        }
    }

    /// Drive both ends until `done`, or give up and say what was outstanding.
    fn until(
        far: &mut FarEnd,
        wire: &Wire,
        forwards: &Forwards<Wire>,
        what: &str,
        mut done: impl FnMut(&mut FarEnd) -> bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            far.step(wire, forwards);
            if done(far) {
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("{what} did not happen");
    }

    fn forwarding() -> (Wire, Arc<ClientWriter<Wire>>) {
        let wire = Wire::default();
        let writer = Arc::new(ClientWriter::new(
            wire.clone(),
            CmdSeq::first(),
            Version::LOCAL,
        ));
        (wire, writer)
    }

    fn one_forward() -> Listeners {
        Listeners::bind(&[ForwardSpec {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            // A test must not race another for a fixed port.
            port: 0,
            target: ForwardTarget {
                host: "intranet".into(),
                port: 80,
            },
        }])
        .expect("loopback binds")
    }

    /// The whole path with the daemon replaced by a `braid_forward::Stream`.
    #[test]
    fn a_local_connection_becomes_a_stream_that_carries_both_directions() {
        let (wire, writer) = forwarding();
        let listeners = one_forward();
        let address = listeners.bound[0].0.local_addr().expect("a bound address");
        let forwards = Forwards::start(listeners, &writer).expect("the forward starts");
        let mut local = TcpStream::connect(address).expect("the listener accepts");
        local
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a read deadline");
        let mut far = FarEnd::new();

        local.write_all(b"GET / HTTP/1.0\r\n").expect("local write");
        until(&mut far, &wire, &forwards, "the request crossed", |far| {
            far.received == b"GET / HTTP/1.0\r\n"
        });
        assert_eq!(
            far.target,
            Some(ForwardTarget {
                host: "intranet".into(),
                port: 80
            }),
            "the open must name what the command line asked for"
        );

        far.stream.write(b"HTTP/1.0 200 OK\r\n", Instant::now());
        far.step(&wire, &forwards);
        let mut answer = [0_u8; 17];
        local.read_exact(&mut answer).expect("the answer arrives");
        assert_eq!(&answer, b"HTTP/1.0 200 OK\r\n");

        // Half close: the local application is done sending and still reads.
        local.shutdown(Shutdown::Write).expect("local half close");
        until(&mut far, &wire, &forwards, "the close crossed", |far| {
            far.stream.peer_finished()
        });

        far.stream.finish();
        until(&mut far, &wire, &forwards, "the answer ended", |far| {
            far.stream.is_done()
        });
        let mut rest = Vec::new();
        local.read_to_end(&mut rest).expect("the socket closes");
        assert!(rest.is_empty(), "nothing follows the end of the answer");
    }

    /// Where the load-only parts are exercised: the reader's credit, the bytes
    /// the backlog refuses and the pump must not consume, the window updates.
    #[test]
    fn a_forward_carries_more_than_a_window_in_each_direction() {
        const BULK: usize = 1024 * 1024;
        let (wire, writer) = forwarding();
        let listeners = one_forward();
        let address = listeners.bound[0].0.local_addr().expect("a bound address");
        let forwards = Forwards::start(listeners, &writer).expect("the forward starts");
        let local = TcpStream::connect(address).expect("the listener accepts");
        let payload: Vec<u8> = (0..BULK)
            .map(|at| u8::try_from(at % 251).unwrap_or(0))
            .collect();

        // Both halves run off this thread: writing a megabyte inline would
        // fill the window and then be the thread meant to drain it.
        let mut sending = local.try_clone().expect("a send handle");
        let sent = payload.clone();
        let sender = thread::spawn(move || {
            sending.write_all(&sent).expect("the local write completes");
            sending.shutdown(Shutdown::Write).expect("local half close");
        });
        let mut receiving = local.try_clone().expect("a receive handle");
        let receiver = thread::spawn(move || {
            let mut got = Vec::new();
            receiving
                .read_to_end(&mut got)
                .expect("the local read ends");
            got
        });

        let mut far = FarEnd::new();
        far.answer = payload.clone();
        until(&mut far, &wire, &forwards, "a megabyte crossed", |far| {
            far.received.len() == BULK && far.answered == BULK && far.stream.peer_finished()
        });
        far.stream.finish();
        until(&mut far, &wire, &forwards, "both halves ended", |far| {
            far.stream.is_done()
        });

        assert_eq!(far.received, payload, "the request crossed intact");
        sender.join().expect("the sending thread");
        let answered = receiver.join().expect("the receiving thread");
        assert_eq!(answered, payload, "the answer crossed intact");
    }

    /// A browser waiting on a tunnel forever is worse than a refused connect.
    #[test]
    fn a_connection_past_the_limit_is_closed_rather_than_queued() {
        let (wire, writer) = forwarding();
        let listeners = one_forward();
        let address = listeners.bound[0].0.local_addr().expect("a bound address");
        let forwards = Forwards::start(listeners, &writer).expect("the forward starts");
        let held: Vec<TcpStream> = (0..MAX_FORWARDS)
            .map(|_| TcpStream::connect(address).expect("the listener accepts"))
            .collect();
        // All of them must be numbered before the next is the one too many.
        let opens = |wire: &Wire| {
            wire.drain()
                .iter()
                .filter(|message| matches!(message, ClientMessage::ForwardOpen { .. }))
                .count()
        };
        let mut numbered = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while numbered < MAX_FORWARDS && Instant::now() < deadline {
            numbered += opens(&wire);
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(numbered, MAX_FORWARDS, "every connection was opened");

        let mut refused = TcpStream::connect(address).expect("the listener still accepts");
        refused
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a read deadline");
        let mut rest = Vec::new();
        refused.read_to_end(&mut rest).expect("the socket closes");
        assert!(rest.is_empty());
        assert_eq!(
            opens(&wire),
            0,
            "a refused connection must not be numbered on the wire"
        );
        drop(held);
        drop(forwards);
    }
}
