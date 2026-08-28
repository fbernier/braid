#![forbid(unsafe_code)]

//! The daemon's half of a `-L` forward: the socket, and the two threads that
//! are allowed to block on it. Ordering and windowing live in [`braid_forward`].
//!
//! A forward belongs to the *client*, not the attachment it arrived on, so one
//! that reconnects inherits the forwards it left open.

use crate::ServerError;
use crate::mailbox::{ActorEvent, Chunk, MailboxSender};
use crate::registry::ForwardSlot;
use braid_forward::Ack;
use braid_proto::{
    ClientId, ForwardResetReason, ForwardTarget, MAX_FORWARD_CHUNK, MAX_FORWARDS, StreamId,
};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Bytes of unwritten payload one forwarded socket may hold; the daemon's
/// memory budget is computed from it. One window, the most the peer can have
/// in flight anyway.
pub(crate) const BACKLOG: usize = braid_forward::FORWARD_WINDOW;

/// What a `ForwardData` frame costs beside its payload: length prefix, tag,
/// stream id, offset, end flag, byte count. The prefix is counted on the
/// datagram path too, where it is stripped before sealing.
pub(crate) const FORWARD_OVERHEAD: usize = 4 + 1 + 4 + 8 + 1 + 4;

/// One segment's worth, so a full read fills exactly one frame on the wire.
const READ_CHUNK: usize = MAX_FORWARD_CHUNK;

/// The kernel's own dial deadline is over two minutes, and the client cannot
/// shorten it: there is no socket yet for a reset to shut down.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

/// Twice what a client may hold open, so every live stream can close and be
/// answered for while a full complement of new ones is opening.
const CLOSED_RING: usize = MAX_FORWARDS * 2;

/// [`crate::ptyin::PtyInput`]'s shape, for its reason: `write_all` blocks when
/// the far end stops reading, and the session actor may never block. Overrun
/// stays in the reliability layer the peer's window is computed from.
struct ForwardWrite {
    buffer: Arc<Mutex<WriteBuffer>>,
    ready: Arc<Condvar>,
}

struct WriteBuffer {
    bytes: Vec<u8>,
    /// Charged against [`BACKLOG`] beside the queue: the writer writes its
    /// batch outside the lock, so ignoring these would admit a second backlog.
    writing: usize,
    /// Write what is left, then shut this socket's write side so the far end
    /// sees the same end of file.
    finished: bool,
    /// The forward is gone; the writer retires without draining.
    closed: bool,
    failed: bool,
}

struct SocketWrite(Arc<TcpStream>);

impl Write for SocketWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

impl ForwardWrite {
    fn new(socket: Arc<TcpStream>) -> Result<Self, ServerError> {
        let half_close = Arc::clone(&socket);
        Self::over(Box::new(SocketWrite(socket)), move || {
            let _ = half_close.shutdown(Shutdown::Write);
        })
    }

    fn over(
        mut writer: Box<dyn Write + Send>,
        half_close: impl FnOnce() + Send + 'static,
    ) -> Result<Self, ServerError> {
        let buffer = Arc::new(Mutex::new(WriteBuffer {
            bytes: Vec::new(),
            writing: 0,
            finished: false,
            closed: false,
            failed: false,
        }));
        let ready = Arc::new(Condvar::new());
        let worker_buffer = Arc::clone(&buffer);
        let worker_ready = Arc::clone(&ready);
        thread::Builder::new()
            .stack_size(crate::IO_STACK)
            .name("brd-forward-write".into())
            .spawn(move || {
                let mut batch = Vec::new();
                loop {
                    {
                        let Ok(mut buffer) = worker_buffer.lock() else {
                            return;
                        };
                        // Before the wait, not after the write: the room the
                        // last batch held is usable the moment the socket has
                        // taken it.
                        buffer.writing = 0;
                        batch.clear();
                        while buffer.bytes.is_empty() {
                            if buffer.closed {
                                return;
                            }
                            if buffer.finished {
                                // Only once the buffer is empty: shutting the
                                // socket over queued bytes would truncate the
                                // last of the transfer.
                                drop(buffer);
                                half_close();
                                return;
                            }
                            let Ok(next) = worker_ready.wait(buffer) else {
                                return;
                            };
                            buffer = next;
                        }
                        std::mem::swap(&mut batch, &mut buffer.bytes);
                        buffer.bytes.clear();
                        buffer.writing = batch.len();
                    }
                    if writer.write_all(&batch).is_err() {
                        if let Ok(mut buffer) = worker_buffer.lock() {
                            buffer.failed = true;
                        }
                        return;
                    }
                }
            })
            .map_err(|_| ServerError::Worker)?;
        Ok(Self { buffer, ready })
    }

    /// A prefix rather than all or nothing. Zero is a full buffer or a socket
    /// that is gone, and both are the caller's cue to stop consuming.
    pub(crate) fn write(&self, bytes: &[u8]) -> usize {
        let Ok(mut buffer) = self.buffer.lock() else {
            return 0;
        };
        if buffer.closed || buffer.failed || buffer.finished {
            return 0;
        }
        let held = buffer.bytes.len() + buffer.writing;
        let take = BACKLOG.saturating_sub(held).min(bytes.len());
        if take == 0 {
            return 0;
        }
        buffer.bytes.extend_from_slice(&bytes[..take]);
        self.ready.notify_one();
        take
    }

    pub(crate) fn shutdown(&self) {
        if let Ok(mut buffer) = self.buffer.lock() {
            buffer.finished = true;
        }
        self.ready.notify_all();
    }

    pub(crate) fn failed(&self) -> bool {
        self.buffer
            .lock()
            .map_or(true, |buffer| buffer.failed || buffer.closed)
    }
}

impl Drop for ForwardWrite {
    fn drop(&mut self) {
        if let Ok(mut buffer) = self.buffer.lock() {
            buffer.closed = true;
        }
        self.ready.notify_all();
    }
}

/// Permission to read, granted by the side that absorbs what is read: taking
/// credit before each read keeps a bulk transfer's overrun waiting in the
/// kernel's receive buffer rather than in the daemon's memory.
struct Credit {
    state: Mutex<CreditState>,
    granted: Condvar,
}

struct CreditState {
    available: usize,
    closed: bool,
}

impl Credit {
    fn new() -> Self {
        Self {
            state: Mutex::new(CreditState {
                available: 0,
                closed: false,
            }),
            granted: Condvar::new(),
        }
    }

    /// A ceiling rather than a sum: the caller passes what the send buffer can
    /// take *now*, recomputed every turn.
    fn grant(&self, bytes: usize) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if bytes <= state.available {
            return;
        }
        state.available = bytes;
        drop(state);
        self.granted.notify_one();
    }

    /// Zero means the forward is gone and the reader must retire.
    fn take(&self, max: usize) -> usize {
        let Ok(mut state) = self.state.lock() else {
            return 0;
        };
        loop {
            if state.closed {
                return 0;
            }
            if state.available > 0 {
                let taken = state.available.min(max);
                state.available -= taken;
                return taken;
            }
            let Ok(next) = self.granted.wait(state) else {
                return 0;
            };
            state = next;
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.granted.notify_all();
    }
}

pub(crate) struct ForwardLink {
    /// Shared with both threads rather than duplicated with `try_clone`: one
    /// forward costs one descriptor, and this is what lets a reset shut down
    /// the socket a reader is parked in.
    socket: Arc<TcpStream>,
    write: ForwardWrite,
}

pub(crate) struct Forward {
    pub(crate) stream: braid_forward::Stream,
    /// `None` while the connect thread is still dialling: this is the
    /// "connected" flag and the socket in one.
    link: Option<ForwardLink>,
    credit: Arc<Credit>,
    /// Read buffers on their way back to the reader thread. `try_send`, so a
    /// receiver that has gone or fallen behind costs one buffer rather than
    /// the actor turn that was giving it back.
    spare: mpsc::SyncSender<Vec<u8>>,
    /// Bytes the send window had no room for. They have already left the
    /// socket, so nothing will produce them again.
    pending: Vec<u8>,
    /// Owed but refused by the client's sink. `poll_ack` reports an owed ack
    /// once, so a lost one costs the peer a retransmission timeout.
    owed_ack: Option<Ack>,
    /// Refunded by its own destructor wherever the forward is retired.
    _charge: ForwardSlot,
}

impl Forward {
    pub(crate) fn open(
        target: ForwardTarget,
        client: ClientId,
        id: StreamId,
        tx: MailboxSender,
        charge: ForwardSlot,
    ) -> Result<Self, ServerError> {
        let credit = Arc::new(Credit::new());
        let worker_credit = Arc::clone(&credit);
        // One slot per bulk-lane frame: that is every buffer this forward can
        // have in flight at once, so a reader that keeps up never allocates.
        let (spare, worker_spare) = mpsc::sync_channel::<Vec<u8>>(crate::mailbox::OUTPUT_LANE);
        thread::Builder::new()
            .stack_size(crate::IO_STACK)
            .name("brd-forward-read".into())
            .spawn(move || dial_and_read(&target, client, id, &tx, &worker_credit, &worker_spare))
            .map_err(|_| ServerError::Worker)?;
        Ok(Self {
            stream: braid_forward::Stream::new(),
            link: None,
            credit,
            spare,
            pending: Vec::new(),
            owed_ack: None,
            _charge: charge,
        })
    }

    pub(crate) fn connected(&mut self, link: ForwardLink) {
        self.link = Some(link);
    }

    /// Takes the chunk rather than borrowing it: the buffer under it is the
    /// reader thread's, and this is the only site that can tell when the
    /// window has finished with it.
    pub(crate) fn absorb(&mut self, chunk: Chunk, now: Instant) {
        let bytes = chunk.bytes();
        if self.pending.is_empty() {
            let taken = self.stream.write(bytes, now);
            self.pending.extend_from_slice(&bytes[taken..]);
        } else {
            self.pending.extend_from_slice(bytes);
            self.drain_pending(now);
        }
        chunk.release(&self.spare);
    }

    fn drain_pending(&mut self, now: Instant) {
        if self.pending.is_empty() {
            return;
        }
        let taken = self.stream.write(&self.pending, now);
        self.pending.drain(..taken);
    }

    pub(crate) fn finish(&mut self, now: Instant) {
        self.drain_pending(now);
        // Only once the window has taken everything read: `finish` closes the
        // half at the current end of the buffer.
        if self.pending.is_empty() {
            self.stream.finish();
        }
    }

    pub(crate) fn owed_ack(&mut self) -> Option<Ack> {
        if let Some(next) = self.stream.poll_ack() {
            self.owed_ack = Some(next);
        }
        self.owed_ack.clone()
    }

    pub(crate) fn acked(&mut self) {
        self.owed_ack = None;
    }

    /// `false` is a reset rather than a stall: the bytes it was given are gone.
    pub(crate) fn drain_to_socket(&mut self) -> bool {
        let Some(link) = &self.link else {
            // Still dialling. What has arrived stays in the receive buffer,
            // which is where the client's window comes from.
            return true;
        };
        if link.write.failed() {
            return false;
        }
        let (first, second) = self.stream.readable();
        let mut taken = link.write.write(first);
        if taken == first.len() {
            taken += link.write.write(second);
        }
        self.stream.consume(taken);
        if self.stream.peer_finished() {
            link.write.shutdown();
        }
        true
    }

    pub(crate) fn grant_credit(&self) {
        // Nothing while a remainder is held: the reader would be reading into
        // room that is already spoken for.
        if self.pending.is_empty() {
            self.credit.grant(self.stream.writable());
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.pending.is_empty() && self.owed_ack.is_none() && self.stream.is_done()
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        // Both threads park with no deadline, and the shutdown is what returns
        // the reader out of `read`.
        self.credit.close();
        if let Some(link) = &self.link {
            let _ = link.socket.shutdown(Shutdown::Both);
        }
    }
}

/// Keyed by `(ClientId, StreamId)`: two clients number their streams
/// independently, and one table between them would collide.
#[derive(Default)]
pub(crate) struct Forwards {
    live: HashMap<(ClientId, StreamId), Forward>,
    /// Ids each client has closed, oldest first: silence is also the correct
    /// answer for a stream whose journalled open has not arrived yet. Bounded
    /// by [`CLOSED_RING`] and by [`Forwards::forget`]; a [`ClientId`] is chosen
    /// by the peer and reaches this map outside the command gate.
    closed: HashMap<ClientId, VecDeque<StreamId>>,
}

impl Forwards {
    pub(crate) fn get_mut(&mut self, client: ClientId, id: StreamId) -> Option<&mut Forward> {
        self.live.get_mut(&(client, id))
    }

    pub(crate) fn contains(&self, client: ClientId, id: StreamId) -> bool {
        self.live.contains_key(&(client, id))
    }

    pub(crate) fn insert(&mut self, client: ClientId, id: StreamId, forward: Forward) {
        self.live.insert((client, id), forward);
    }

    pub(crate) fn held_by(&self, client: ClientId) -> usize {
        self.live
            .keys()
            .filter(|(owner, _)| *owner == client)
            .count()
    }

    pub(crate) fn was_closed(&self, client: ClientId, id: StreamId) -> bool {
        self.closed
            .get(&client)
            .is_some_and(|ring| ring.contains(&id))
    }

    /// Recorded even for a forward that never existed — one refused at a limit
    /// — because the client's payload does not wait for the open.
    pub(crate) fn retire(&mut self, client: ClientId, id: StreamId) {
        self.live.remove(&(client, id));
        let ring = self.closed.entry(client).or_default();
        if ring.contains(&id) {
            return;
        }
        if ring.len() == CLOSED_RING {
            ring.pop_front();
        }
        ring.push_back(id);
    }

    /// The session says when by evicting that client's command stream, whose
    /// sequence numbers restart if it ever returns.
    pub(crate) fn forget(&mut self, client: ClientId) {
        self.live.retain(|(owner, _), _| *owner != client);
        self.closed.remove(&client);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&(ClientId, StreamId), &mut Forward)> {
        self.live.iter_mut()
    }

    pub(crate) fn deadline(&self, now: Instant) -> Option<Duration> {
        self.live
            .values()
            .filter_map(|forward| forward.stream.deadline(now))
            .min()
    }
}

fn dial_and_read(
    target: &ForwardTarget,
    client: ClientId,
    id: StreamId,
    tx: &MailboxSender,
    credit: &Credit,
    spare: &mpsc::Receiver<Vec<u8>>,
) {
    let socket = match dial(target) {
        Ok(socket) => Arc::new(socket),
        Err(reason) => {
            let _ = tx.send(ActorEvent::ForwardConnected {
                client,
                stream: id,
                link: Err(reason),
            });
            return;
        }
    };
    let Ok(write) = ForwardWrite::new(Arc::clone(&socket)) else {
        let _ = tx.send(ActorEvent::ForwardConnected {
            client,
            stream: id,
            link: Err(ForwardResetReason::Internal),
        });
        return;
    };
    if tx
        .send(ActorEvent::ForwardConnected {
            client,
            stream: id,
            link: Ok(ForwardLink {
                socket: Arc::clone(&socket),
                write,
            }),
        })
        .is_err()
    {
        return;
    }
    loop {
        // Before the read rather than after it: a read already made is a read
        // whose bytes have to go somewhere.
        let want = credit.take(READ_CHUNK);
        if want == 0 {
            return;
        }
        // Read into the buffer that travels, not into one it is copied out of:
        // a forward at speed is one 32 KiB allocation and one 32 KiB copy per
        // chunk otherwise, both on the thread that could be reading instead.
        let mut chunk = Chunk::take(spare, READ_CHUNK);
        match (&*socket).read(&mut chunk.room()[..want]) {
            Ok(0) => break,
            Ok(len) => {
                // The blocking send is the backpressure: a forward that
                // outruns the actor parks here rather than queueing.
                if tx
                    .send(ActorEvent::ForwardBytes {
                        client,
                        stream: id,
                        bytes: chunk.filled(len),
                    })
                    .is_err()
                {
                    return;
                }
            }
            // Rare enough to let the buffer go rather than thread it through.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                let _ = tx.send(ActorEvent::ForwardEof {
                    client,
                    stream: id,
                    failed: true,
                });
                return;
            }
        }
    }
    let _ = tx.send(ActorEvent::ForwardEof {
        client,
        stream: id,
        failed: false,
    });
}

fn dial(target: &ForwardTarget) -> Result<TcpStream, ForwardResetReason> {
    let addresses = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|_| ForwardResetReason::Unreachable)?;
    // A name that resolved to nothing is still a name that named nothing.
    let mut refused = ForwardResetReason::Unreachable;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_DEADLINE) {
            Ok(socket) => {
                // Nagle on a tunnelled ssh is the round trip this whole
                // protocol exists to keep short.
                let _ = socket.set_nodelay(true);
                return Ok(socket);
            }
            Err(_) => refused = ForwardResetReason::Refused,
        }
    }
    Err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::ClientStream;
    use crate::testing::*;
    use braid_proto::MAX_ATTACHMENTS;
    use std::net::TcpListener;

    /// A far end that has stopped reading must not stop the actor that would
    /// otherwise deliver the reset.
    #[test]
    fn a_socket_that_stops_reading_does_not_block_the_caller() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let socket = TcpStream::connect(address).expect("connect");
        // Accepted and then never read: what fills is the kernel's buffers and
        // then this one.
        let _accepted = listener.accept().expect("accept");
        let write = ForwardWrite::new(Arc::new(socket)).expect("writer");
        let chunk = vec![b'x'; 64 * 1024];
        let mut refused = false;
        for _ in 0..256 {
            if write.write(&chunk) < chunk.len() {
                refused = true;
                break;
            }
        }
        assert!(refused, "the backlog must be bounded");
    }

    #[test]
    fn credit_is_a_ceiling_and_a_close_releases_the_reader() {
        let credit = Credit::new();
        credit.grant(1000);
        credit.grant(500);
        assert_eq!(credit.take(400), 400);
        assert_eq!(credit.take(10_000), 600, "grants must not accumulate");
        credit.close();
        assert_eq!(credit.take(10), 0, "a closed credit retires its reader");
    }

    #[test]
    fn a_name_that_does_not_resolve_is_unreachable_and_a_dead_port_is_refused() {
        let unresolvable = ForwardTarget {
            host: "no-such-host.invalid".into(),
            port: 9,
        };
        assert_eq!(
            dial(&unresolvable).err(),
            Some(ForwardResetReason::Unreachable)
        );

        // A port bound and immediately dropped is the closest thing to a
        // guaranteed closed port on a machine nothing else is using.
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let dead = ForwardTarget {
            host: address.ip().to_string(),
            port: address.port(),
        };
        assert_eq!(dial(&dead).err(), Some(ForwardResetReason::Refused));
    }

    /// The ring tells "already closed" from "not opened yet", and must not grow
    /// without bound while it does so.
    #[test]
    fn the_closed_ring_remembers_recent_streams_and_forgets_old_ones() {
        let mut forwards = Forwards::default();
        let owner = ClientId::from_bytes([7; 16]);
        let mut id = StreamId::first();
        for _ in 0..CLOSED_RING {
            forwards.retire(owner, id);
            id = id.next();
        }
        assert!(forwards.was_closed(owner, StreamId::first()));
        forwards.retire(owner, id);
        assert!(
            !forwards.was_closed(owner, StreamId::first()),
            "the ring is unbounded"
        );
        assert!(forwards.was_closed(owner, id));
        assert!(
            !forwards.was_closed(ClientId::from_bytes([8; 16]), id),
            "one client's closed stream must not answer for another's"
        );
    }

    /// Counted only in the queue, the batch the writer holds outside the lock
    /// would let a second whole backlog in beside it.
    #[test]
    fn what_the_writer_is_holding_is_charged_against_the_backlog_too() {
        let (writer, took, release) = holding();
        let write = ForwardWrite::over(Box::new(writer), || {}).expect("writer");
        let chunk = vec![b'x'; 64 * 1024];
        assert_eq!(
            write.write(&chunk),
            chunk.len(),
            "an empty queue must take the first"
        );
        let mut admitted = took.recv().expect("the writer takes the first batch");
        loop {
            let took = write.write(&chunk);
            if took == 0 {
                break;
            }
            admitted += took;
            assert!(
                admitted <= BACKLOG,
                "{admitted} bytes are queued or in flight against a {BACKLOG}-byte ceiling"
            );
        }
        let _ = release.send(());
    }

    /// `Forwards::closed` is reached outside the command gate, so an entry
    /// outliving its client is one a long-lived `-L` gains per reconnect.
    #[test]
    fn a_client_the_session_forgets_takes_its_closed_streams_with_it() {
        let (mut actor, _mailbox) = forward_only_actor();
        let first = client(1);
        let stream = StreamId::first();
        actor.forwards.retire(first, stream);
        assert!(actor.forwards.was_closed(first, stream));

        // Every client that ever attached, oldest first: the first is evicted
        // once the retired list is past its bound.
        for number in 1..=u8::try_from(MAX_ATTACHMENTS + 1).expect("a small bound") {
            actor.retire(ClientStream::new(client(number)));
        }

        assert!(
            !actor.forwards.was_closed(first, stream),
            "a client the session has forgotten still holds a table entry"
        );
    }
}
