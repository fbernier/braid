#![forbid(unsafe_code)]

//! The queue in front of one attached client, drained by a thread of its own.
//! The screen lane is one slot a newer screen overwrites in place, keeping the
//! position it already held in the order.

use braid_proto::{MAX_OUTPUT_CHUNK, ServerMessage, Version};
use std::collections::VecDeque;
use std::io::{self, IoSlice, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Bytes of byte-stream output that may wait for one client before the session
/// stops streaming and switches to whole screens. Bytes rather than frames:
/// thirty-two frames is anything from a kilobyte to two megabytes.
pub const STREAM_LIMIT: usize = 256 * 1024;

/// Room past [`STREAM_LIMIT`] reserved for the messages a client cannot be left
/// without: an exit, a detach, or the error explaining either.
const CONTROL_SLACK: usize = 64 * 1024;

/// Bytes of the order offered to the transport in one turn.
const BATCH: usize = 32 * 1024;

/// Frames offered in one call. Sixty-four covers a 32 KiB batch of output
/// chunks and one cut into datagram-sized pieces alike, off the heap.
const VECTORED: usize = 64;

/// Frame buffers kept for the producer: one batch's worth, which is what can be
/// in flight at once.
const SPARE_FRAMES: usize = VECTORED;

/// Keep a spent frame for the producer, under the bound a pool of screen pieces
/// would otherwise grow to. A screen piece's buffer is half a megabyte and the
/// next output frame needs a few kilobytes of it, so keeping one would trade an
/// allocation for resident memory.
pub(crate) fn recycle(spare: &mut Vec<Vec<u8>>, frame: Vec<u8>) {
    if spare.len() < SPARE_FRAMES && frame.capacity() <= MAX_OUTPUT_CHUNK {
        spare.push(frame);
    }
}

/// Bytes of screen one attachment may hold waiting before the session is told
/// it is composing too much. The lane is one slot deep, so [`STREAM_LIMIT`] has
/// nothing to say about it, and a full repaint at `GridSize::MAX_COLS` by
/// `MAX_ROWS` is megabytes held per stalled attachment.
const SCREEN_LIMIT: usize = 512 * 1024;

/// Bytes of forwarded payload that may wait for one client. A segment refused
/// here is still owed by the forward's own retransmission buffer, so this is a
/// lane of its own rather than room borrowed from the stream or the slack.
pub const FORWARD_LANE: usize = 64 * 1024;

/// What one attachment costs the daemon at its ceilings.
pub const CEILING: usize = STREAM_LIMIT + CONTROL_SLACK + SCREEN_LIMIT + FORWARD_LANE;

/// How long the writer waits before retrying a transport that refused for want
/// of window. Short against the datagram transport's own 250 ms tick.
const BLOCKED_PARK: Duration = Duration::from_millis(10);

/// Frames rather than one gathered buffer: a stream takes them all in one
/// `writev`, and a datagram *is* one frame, so gathering would only have to be
/// walked back apart along the length prefixes it just wrote.
pub trait FrameWriter {
    /// Take as much of `frames` as the transport will accept, in order, and say
    /// how many bytes that was - counted end to end, so a prefix of one frame
    /// is reported as that prefix and the sink resumes there.
    ///
    /// `packed` names the frames whose payload has already been through the
    /// codec; a transport that does not compress ignores it.
    fn write_frames(&mut self, frames: &[IoSlice<'_>], packed: FrameSet) -> io::Result<usize>;

    fn flush(&mut self) -> io::Result<()>;
}

/// Which frames of one `write_frames` call arrive already packed, by index.
///
/// A set rather than a second array to walk: [`VECTORED`] is exactly this
/// wide, so the whole answer is one register and the offer stays allocation
/// free.
#[derive(Clone, Copy, Default)]
pub struct FrameSet(u64);

const _: () = assert!(VECTORED == u64::BITS as usize);

/// How the pieces of one screen arrive. A datagram cut has to pack every piece
/// to learn whether it fits the path, so the packing that measured the cut is
/// the packing that is sent; a stream cut carries the frames as encoded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Raw,
    Packed,
}

/// One screen as its transport will carry it. The pieces and their coding
/// travel together: one cut produces them all, under one framing.
pub struct Cut {
    pub pieces: Vec<Vec<u8>>,
    pub coding: Coding,
}

impl Cut {
    /// Pieces as they were encoded, which is what every framing but the
    /// datagram's produces.
    #[cfg(test)]
    pub fn raw(pieces: Vec<Vec<u8>>) -> Self {
        Self {
            pieces,
            coding: Coding::Raw,
        }
    }
}

impl FrameSet {
    pub fn contains(self, index: usize) -> bool {
        index < u64::BITS as usize && self.0 & (1 << index) != 0
    }

    fn insert(&mut self, index: usize) {
        debug_assert!(index < VECTORED, "a batch offers at most `VECTORED` frames");
        self.0 |= 1 << index;
    }
}

/// A stream carries the frames as they were encoded; only the datagram framing
/// compresses, so there is nothing here for `packed` to say.
impl<W: Write + ?Sized> FrameWriter for W {
    fn write_frames(&mut self, frames: &[IoSlice<'_>], _: FrameSet) -> io::Result<usize> {
        self.write_vectored(frames)
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(self)
    }
}

#[derive(Debug)]
pub enum SinkError {
    /// Not queued: the client is not draining and the caller must degrade
    /// rather than wait.
    Full,
    /// The client is gone, or the frame does not fit the protocol and never
    /// will.
    Unusable,
}

#[derive(Clone, Copy)]
enum Position {
    Back,
    /// Ahead of everything queued: an `Exit` pushed behind 256 KiB of stream
    /// frames waits them out on exactly the client that stopped draining them.
    Front,
}

/// The screen's payload lives beside the queue, so a newer screen replaces the
/// older one without moving in the order. Output and reserved frames are
/// separate variants because [`AttachmentSink::discard_stream`] has to tell
/// them apart and the difference is not in the bytes.
enum Slot {
    Stream(Vec<u8>),
    /// A frame drawing on the room reserved past [`STREAM_LIMIT`]. Nothing a
    /// screen carries, so nothing a screen may drop.
    Control(Vec<u8>),
    /// No screen supersedes one, and it must not spend the reserved room.
    Forward(Vec<u8>),
    Screen,
}

impl Slot {
    /// What this entry occupies of its own lane. The screen slot occupies none:
    /// its payload is replaceable, so it cannot grow the queue however long the
    /// client stalls, and [`Queue::screen`] weighs it instead.
    fn bytes(&self) -> usize {
        match self {
            Self::Stream(frame) | Self::Control(frame) | Self::Forward(frame) => frame.len(),
            Self::Screen => 0,
        }
    }
}

/// What the screen lane is costing the attachment holding one. Reported rather
/// than refused: the ledger has already planned against this screen being sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenPressure {
    Clear,
    /// The caller should not compose another screen until this one is taken.
    Over,
}

const fn is_terminal(message: &ServerMessage) -> bool {
    matches!(
        message,
        ServerMessage::Exit { .. } | ServerMessage::Detached { .. } | ServerMessage::Reject { .. }
    )
}

struct Queue {
    order: VecDeque<Slot>,
    /// The pieces of the newest screen. One `Slot::Screen` is in `order`
    /// exactly while this is non-empty.
    pieces: Vec<Vec<u8>>,
    /// How those pieces are framed, carried alongside them because one cut
    /// produces them all under one framing.
    coding: Coding,
    /// What that screen weighs, which [`Slot::bytes`] deliberately does not.
    screen: Lane,
    stream: Lane,
    /// Counted apart from `stream` so a busy tunnel and a busy terminal cannot
    /// spend each other's room.
    forward: Lane,
    /// Subtracted from [`Queue::outstanding`]: counting a forward there makes a
    /// client with a busy tunnel look like a terminal that stopped draining,
    /// and pins the session in whole-screen repaints while it carries anything.
    forward_entries: usize,
    /// A batch the writer has taken but not yet written. Counted, because a
    /// writer blocked inside `write_all` has emptied the queue and delivered
    /// nothing; it stays set across a `WouldBlock` for the same reason.
    in_flight: bool,
    /// Frame buffers the transport has finished with, waiting to be filled
    /// again by the session that encoded them.
    spare: Vec<Vec<u8>>,
    closed: bool,
}

/// One lane's bytes: those queued, and those the writer took and has not given
/// back. Both charged against the limit, because a batch the writer holds is
/// memory this attachment owns, and [`CEILING`] is what the daemon admits
/// attachments against.
#[derive(Default)]
struct Lane {
    queued: usize,
    taken: usize,
}

impl Lane {
    /// What this lane holds in all, which is what its limit bounds.
    const fn charged(&self) -> usize {
        self.queued + self.taken
    }

    /// The writer has taken these bytes. They are still this lane's.
    const fn take(&mut self, bytes: usize) {
        self.queued -= bytes;
        self.taken += bytes;
    }

    const fn take_all(&mut self) {
        self.taken += self.queued;
        self.queued = 0;
    }

    /// The transport is done with the batch this lane contributed to.
    const fn release(&mut self) {
        self.taken = 0;
    }
}

impl Queue {
    /// What the lock-free mirror counts: the entries waiting and the batch the
    /// writer holds.
    fn outstanding(&self) -> usize {
        self.order.len().saturating_sub(self.forward_entries) + usize::from(self.in_flight)
    }

    /// Take the front of the order into `batch`, marking it in flight. The
    /// screen slot empties whole: taking its pieces one at a time would let
    /// piece two supersede piece one of the same screen.
    fn fill(&mut self, batch: &mut Batch) {
        while batch.owed < BATCH {
            let Some(slot) = self.order.pop_front() else {
                break;
            };
            match slot {
                Slot::Stream(frame) | Slot::Control(frame) => {
                    self.stream.take(frame.len());
                    batch.push(frame, Coding::Raw);
                }
                Slot::Forward(frame) => {
                    self.forward.take(frame.len());
                    self.forward_entries -= 1;
                    batch.push(frame, Coding::Raw);
                }
                Slot::Screen => {
                    self.screen.take_all();
                    let coding = self.coding;
                    for piece in self.pieces.drain(..) {
                        batch.push(piece, coding);
                    }
                }
            }
        }
        self.in_flight = true;
    }
}

struct Batch {
    frames: Vec<Vec<u8>>,
    /// How each of `frames` is framed, by the same index. Parallel to `frames`
    /// rather than a field on each: the frame is a plain buffer that travels
    /// back to the producer's spare pool, and a wrapper on it would have to be
    /// unwrapped at every one of those hand-offs.
    coding: Vec<Coding>,
    /// Counted end to end rather than per frame: a transport that stops
    /// mid-frame has to be resumed at that byte, not at the frame it fell in.
    owed: usize,
    sent: usize,
    /// The first frame `sent` has not passed, and the bytes of every frame
    /// ahead of it. `sent` only grows, so this only moves forward: without it
    /// a transport that takes one frame per call - which is what the datagram
    /// writer is - rescans the whole batch once for every frame in it.
    at: usize,
    ahead: usize,
}

impl Batch {
    const fn new() -> Self {
        Self {
            frames: Vec::new(),
            coding: Vec::new(),
            owed: 0,
            sent: 0,
            at: 0,
            ahead: 0,
        }
    }

    fn push(&mut self, frame: Vec<u8>, coding: Coding) {
        self.owed += frame.len();
        self.frames.push(frame);
        self.coding.push(coding);
    }

    const fn is_spent(&self) -> bool {
        self.sent == self.owed
    }

    fn clear(&mut self) {
        self.frames.clear();
        self.coding.clear();
        self.owed = 0;
        self.sent = 0;
        self.at = 0;
        self.ahead = 0;
    }

    /// Take `taken` bytes off what is owed and step the cursor past whatever
    /// that finished.
    fn advance(&mut self, taken: usize) {
        self.sent += taken;
        while let Some(frame) = self.frames.get(self.at) {
            let end = self.ahead + frame.len();
            if end > self.sent {
                break;
            }
            self.ahead = end;
            self.at += 1;
        }
    }

    /// Fill `slices` with the frames the transport has not taken: the one
    /// straddling `sent` from the byte it stopped on, and nothing wholly behind
    /// it, or the link that could least afford it gets output twice.
    fn remainder<'a>(&'a self, slices: &mut [IoSlice<'a>]) -> (usize, FrameSet) {
        // Every frame from the cursor on is owed by construction, so the only
        // partial one is the first.
        let mut offset = self.sent - self.ahead;
        let mut filled = 0;
        let mut packed = FrameSet::default();
        for (frame, &coding) in self.frames[self.at..].iter().zip(&self.coding[self.at..]) {
            if filled == slices.len() {
                break;
            }
            slices[filled] = IoSlice::new(&frame[offset..]);
            if coding == Coding::Packed {
                packed.insert(filled);
            }
            filled += 1;
            offset = 0;
        }
        (filled, packed)
    }
}

enum Pump {
    Done,
    /// Refused for want of room. The prefix taken is consumed; the remainder
    /// stays in the batch.
    Blocked,
    Failed,
}

/// Not `write_all`: it reports an error without saying how many bytes it had
/// already written, and retrying a batch whose prefix was accepted duplicates
/// output on exactly the link that could least afford it.
fn pump(output: &mut dyn FrameWriter, batch: &mut Batch) -> Pump {
    while !batch.is_spent() {
        // Rebuilt per call: the slices borrow the frames, and what is offered
        // changes with every byte the transport takes.
        let offered = {
            let mut slices = [IoSlice::new(&[]); VECTORED];
            let (filled, packed) = batch.remainder(&mut slices);
            output.write_frames(&slices[..filled], packed)
        };
        match offered {
            // A writer that takes nothing and reports no reason cannot be
            // waited on: there is no event that would change the answer.
            Ok(0) => return Pump::Failed,
            Ok(taken) => batch.advance(taken),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Pump::Blocked,
            Err(_) => return Pump::Failed,
        }
    }
    match output.flush() {
        Ok(()) => Pump::Done,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Pump::Blocked,
        Err(_) => Pump::Failed,
    }
}

/// Offer what is still queued, once, to a transport whose producer has gone.
///
/// The unsent remainder of the blocked batch is dropped on purpose: nobody is
/// left to ask for the repaint that would repair it. What may be *behind* it is
/// the session's last word, which is why [`AttachmentSink::send`] puts a
/// terminal message at the front of the order.
fn last_words(output: &mut dyn FrameWriter, worker: &Shared, batch: &mut Batch) {
    batch.clear();
    // The queue is closed, so this cannot wait: it either fills from what is
    // left or says there is nothing.
    if worker.take(batch) {
        let _ = pump(output, batch);
    }
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    /// [`Queue::closed`] and [`Queue::outstanding`], mirrored for readers that
    /// must not take the lock.
    ///
    /// `Relaxed` is enough: nothing is published *through* these, and both are
    /// stored only inside the queue's critical section, so the mirror can lag
    /// but can never describe a state the queue never held. `closed` only ever
    /// goes true, and only a producer makes `outstanding` non-zero while the
    /// writer recomputes it under the lock.
    closed: AtomicBool,
    outstanding: AtomicUsize,
}

impl Shared {
    fn publish(&self, queue: &Queue) {
        self.closed.store(queue.closed, Ordering::Relaxed);
        self.outstanding
            .store(queue.outstanding(), Ordering::Relaxed);
    }

    fn close(&self) {
        match self.queue.lock() {
            Ok(mut queue) => {
                queue.closed = true;
                self.publish(&queue);
            }
            // A poisoned queue can publish nothing ever again, and `closed`
            // only goes true: storing it out here cannot invent a close.
            Err(_) => self.closed.store(true, Ordering::Relaxed),
        }
        self.ready.notify_all();
    }

    /// Wait until there is something to send, and take it. `false` retires the
    /// writer: the queue is closed, or its lock is poisoned.
    fn take(&self, batch: &mut Batch) -> bool {
        let Ok(mut queue) = self.queue.lock() else {
            return false;
        };
        while queue.order.is_empty() {
            if queue.closed {
                return false;
            }
            let Ok(next) = self.ready.wait(queue) else {
                return false;
            };
            queue = next;
        }
        queue.fill(batch);
        self.publish(&queue);
        true
    }

    /// Wait out a transport that refused a write, or retire.
    ///
    /// On the condvar rather than in a sleep, so a close retires this writer at
    /// once. A producer's own notify wakes it early, which is what makes the
    /// deadline a ceiling rather than a latency.
    fn park_blocked(&self) -> bool {
        let Ok(mut queue) = self.queue.lock() else {
            return false;
        };
        let deadline = Instant::now() + BLOCKED_PARK;
        loop {
            if queue.closed {
                return false;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return true;
            };
            let Ok((next, _)) = self.ready.wait_timeout(queue, left) else {
                return false;
            };
            queue = next;
        }
    }

    /// Note that the batch has gone out, or that the transport is gone. Without
    /// the `closed` half the queue keeps accepting until the byte budget
    /// overruns, and the actor reads that as backpressure and enters
    /// whole-screen sync mode for a client that is already gone.
    fn settle(&self, failed: bool) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.in_flight = false;
            queue.closed |= failed;
            self.publish(&queue);
        }
    }

    /// Hand a spent batch's buffers back to the producer, and give the lanes the
    /// room it held.
    fn retire(&self, batch: &mut Batch) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.stream.release();
            queue.forward.release();
            queue.screen.release();
            for frame in batch.frames.drain(..) {
                recycle(&mut queue.spare, frame);
            }
        }
        batch.clear();
    }
}

/// The producer side of the queue, counted across the sink's clones. The writer
/// parks with no deadline, so `closed` is the only thing that can retire it;
/// tying that to the last clone going away makes teardown a property of
/// ownership rather than of remembering `close` on every path.
struct Producer(Arc<Shared>);

impl Drop for Producer {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[derive(Clone)]
pub struct AttachmentSink {
    producer: Arc<Producer>,
    /// What this connection negotiated. Every frame that leaves here is written
    /// at it, which is why it lives on the sink.
    version: Version,
}

impl AttachmentSink {
    pub fn new<W: FrameWriter + Send + 'static>(
        mut output: W,
        version: Version,
    ) -> Result<Self, crate::ServerError> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                order: VecDeque::new(),
                pieces: Vec::new(),
                coding: Coding::Raw,
                screen: Lane::default(),
                stream: Lane::default(),
                forward: Lane::default(),
                forward_entries: 0,
                spare: Vec::new(),
                in_flight: false,
                closed: false,
            }),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
            outstanding: AtomicUsize::new(0),
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .stack_size(crate::IO_STACK)
            // Not `brd-attachment`: the daemon's per-connection frame reader
            // already had that name, so `perf` and `thread apply all bt` could
            // not tell the two apart.
            .name("brd-sink".into())
            .spawn(move || {
                let mut batch = Batch::new();
                loop {
                    if batch.is_spent() {
                        worker.retire(&mut batch);
                        if !worker.take(&mut batch) {
                            break;
                        }
                    }
                    match pump(&mut output, &mut batch) {
                        Pump::Done => worker.settle(false),
                        // Nothing is taken from the queue while a remainder is
                        // owed, so a screen waiting behind this batch is still
                        // superseded in place by a newer one.
                        Pump::Blocked => {
                            if !worker.park_blocked() {
                                last_words(&mut output, &worker, &mut batch);
                                break;
                            }
                        }
                        Pump::Failed => {
                            worker.settle(true);
                            break;
                        }
                    }
                }
                let _ = output.flush();
            })
            .map_err(|_| crate::ServerError::Worker)?;
        Ok(Self {
            producer: Arc::new(Producer(shared)),
            version,
        })
    }

    pub fn version(&self) -> Version {
        self.version
    }

    fn shared(&self) -> &Shared {
        &self.producer.0
    }

    /// Queue a message the client cannot be left without, on reserved room
    /// rather than in competition with the byte stream. The ones that end the
    /// attachment also jump it: an `Exit` a client never learns about is the
    /// failure the reservation exists to prevent.
    pub fn send(&self, message: &ServerMessage) -> Result<(), SinkError> {
        let frame = message
            .encode(self.version)
            .map_err(|_| SinkError::Unusable)?;
        let position = if is_terminal(message) {
            Position::Front
        } else {
            Position::Back
        };
        self.push(Slot::Control(frame), STREAM_LIMIT + CONTROL_SLACK, position)
    }

    /// Queue one encoded chunk of the byte stream. `Full` is the signal that
    /// starts a sync episode, not a reason for the session to wait.
    pub fn send_output(&self, frame: Vec<u8>) -> Result<(), SinkError> {
        self.push(Slot::Stream(frame), STREAM_LIMIT, Position::Back)
    }

    /// Queue one encoded segment of a forwarded connection. `Full` is not loss -
    /// the forward's retransmission buffer still owes the segment - so the
    /// caller must not report it transmitted when this refuses it.
    pub fn send_forward(&self, frame: Vec<u8>) -> Result<(), SinkError> {
        self.push(Slot::Forward(frame), FORWARD_LANE, Position::Back)
    }

    /// Queue one screen as its pieces, replacing a screen already waiting, and
    /// report what the waiting screen weighs.
    ///
    /// The cut says whether its pieces have already been through the codec,
    /// which is what a datagram cut produces: it has to pack every piece to
    /// learn whether it fits the path, so packing them again to send them would
    /// be the whole screen deflated twice.
    ///
    /// Never `Full`: the queue depth for screens is one however slow the link
    /// is. Superseding is safe because the ledger only clears damage a client
    /// has confirmed, so a newer delta always names a superset of the rows the
    /// one it replaced did. The pieces arrive and leave together, or piece two
    /// would supersede piece one of the same screen.
    pub fn send_screen(&self, cut: Cut) -> Result<ScreenPressure, SinkError> {
        let shared = self.shared();
        let mut queue = shared.queue.lock().map_err(|_| SinkError::Unusable)?;
        if queue.closed {
            return Err(SinkError::Unusable);
        }
        if cut.pieces.is_empty() {
            return Ok(ScreenPressure::Clear);
        }
        if queue.pieces.is_empty() {
            queue.order.push_back(Slot::Screen);
        }
        queue.screen.queued = cut.pieces.iter().map(Vec::len).sum();
        queue.pieces = cut.pieces;
        queue.coding = cut.coding;
        // What this client holds in all, not just what is waiting: a screen the
        // transport took and has not delivered is one it still owns.
        let pressure = if queue.screen.charged() > SCREEN_LIMIT {
            ScreenPressure::Over
        } else {
            ScreenPressure::Clear
        };
        shared.publish(&queue);
        shared.ready.notify_one();
        Ok(pressure)
    }

    /// Drop the byte stream the screen that follows supersedes.
    ///
    /// A screen carries `next_off` and the client jumps there unconditionally,
    /// so output queued ahead of it is a quarter megabyte the client throws
    /// away on arrival. Safe for the same reason superseding a screen is. The
    /// reserved frames and the waiting screen stay; what the writer has already
    /// batched is past recall.
    pub fn discard_stream(&self) {
        // A poisoned queue is a writer that died mid-batch and a closed one is
        // a client that is gone: neither has a stream worth shortening, and
        // neither is worth panicking the session actor over.
        let Ok(mut queue) = self.shared().queue.lock() else {
            return;
        };
        let mut kept = 0;
        queue.order.retain(|slot| match slot {
            Slot::Stream(_) => false,
            Slot::Control(frame) => {
                kept += frame.len();
                true
            }
            // A forwarded byte cannot be regenerated and no screen carries one,
            // so taking these would be silent data loss on a connection the
            // user believes is intact.
            Slot::Forward(_) | Slot::Screen => true,
        });
        // Recomputed rather than zeroed: the surviving control frames still
        // occupy the room the next `push` is measured against, and so does the
        // batch the writer is holding.
        queue.stream.queued = kept;
        self.shared().publish(&queue);
    }

    fn push(&self, slot: Slot, limit: usize, position: Position) -> Result<(), SinkError> {
        let shared = self.shared();
        let mut queue = shared.queue.lock().map_err(|_| SinkError::Unusable)?;
        if queue.closed {
            return Err(SinkError::Unusable);
        }
        let bytes = slot.bytes();
        // One accounting site for both lanes: a second `push` beside this one
        // is how a lane ends up bounded by the other lane's number.
        let forward = matches!(slot, Slot::Forward(_));
        let lane = if forward {
            &mut queue.forward
        } else {
            &mut queue.stream
        };
        if lane.charged().saturating_add(bytes) > limit {
            return Err(SinkError::Full);
        }
        lane.queued += bytes;
        if forward {
            queue.forward_entries += 1;
        }
        match position {
            Position::Back => queue.order.push_back(slot),
            Position::Front => queue.order.push_front(slot),
        }
        shared.publish(&queue);
        shared.ready.notify_one();
        Ok(())
    }

    /// Whether the transport has taken everything handed to it - the honest
    /// condition for leaving sync mode, since quiescence alone pins any session
    /// with a progress bar in whole-screen mode. A closed sink never answers
    /// true.
    pub fn is_drained(&self) -> bool {
        let shared = self.shared();
        !shared.closed.load(Ordering::Relaxed) && shared.outstanding.load(Ordering::Relaxed) == 0
    }

    /// Set by `close`, and by the writer thread the moment its transport
    /// refuses a write.
    pub fn is_closed(&self) -> bool {
        self.shared().closed.load(Ordering::Relaxed)
    }

    /// Take back the frame buffers the transport has finished with. A datagram
    /// path cuts a 64 KiB read into fifty-odd frames: at [`MAX_ATTACHMENTS`]
    /// that is several hundred allocations and frees per PTY read, for buffers
    /// vacated a few microseconds earlier.
    pub fn reclaim(&self, spare: &mut Vec<Vec<u8>>) {
        // A poisoned queue is a writer that died mid-batch: there is nothing to
        // reclaim and nothing worth panicking the session actor over.
        let Ok(mut queue) = self.shared().queue.lock() else {
            return;
        };
        spare.append(&mut queue.spare);
    }

    pub fn close(&self) {
        self.shared().close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A transport that is already gone.
    struct Refusing;

    impl Write for Refusing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("the client is gone"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Announces the writer thread's exit: the worker owns its output, so
    /// dropping this is the thread retiring.
    struct Retiring(mpsc::Sender<()>);

    impl Write for Retiring {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Retiring {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    /// The fakes below are written against a whole batch, so gathering gives
    /// them the bytes the sink hands the transport as frames.
    fn gathered(frames: &[IoSlice<'_>]) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|frame| frame.iter())
            .copied()
            .collect()
    }

    /// A transport whose window never opens, recording every batch it was
    /// offered and taking none of it.
    struct Shut(Arc<Mutex<Vec<Vec<u8>>>>);

    impl Write for Shut {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("offers").push(buf.to_vec());
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }
        fn write_vectored(&mut self, frames: &[IoSlice<'_>]) -> std::io::Result<usize> {
            self.write(&gathered(frames))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Waits for a shared log to hold at least `wanted` entries, and returns it.
    fn wait_for<T: Clone + std::fmt::Debug>(log: &Arc<Mutex<Vec<T>>>, wanted: usize) -> Vec<T> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = log.lock().expect("sink log").clone();
            if seen.len() >= wanted {
                return seen;
            }
            assert!(
                Instant::now() < deadline,
                "the writer never caught up: {seen:?}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn exit_frame() -> Vec<u8> {
        ServerMessage::Exit { code: 0 }
            .encode(Version::LOCAL)
            .expect("encode exit")
    }

    /// A writer parked on a shut window whose producer goes away must still
    /// offer the session's last word: an `Exit` nobody was ever offered is a
    /// client that waits out its silence deadline for a shell that ended.
    #[test]
    fn a_terminal_message_queued_against_a_shut_window_is_still_offered_once() {
        let offers = Arc::new(Mutex::new(Vec::new()));
        let sink =
            AttachmentSink::new(Box::new(Shut(Arc::clone(&offers))), Version::LOCAL).expect("sink");
        sink.send_output(vec![0xAA; 8]).expect("stream frame");
        // Only once the writer has taken that frame and been refused is what
        // follows a queue rather than a race with the first `fill`.
        let before = wait_for(&offers, 1).len();
        sink.send(&ServerMessage::Exit { code: 0 }).expect("exit");
        // The producer going away closes the queue while the window is shut.
        drop(sink);

        let exit = exit_frame();
        let seen = wait_for(&offers, before + 1);
        let carried = seen
            .iter()
            .filter(|batch| batch.starts_with(exit.as_slice()))
            .count();
        assert_eq!(carried, 1, "the exit was offered {carried} times: {seen:?}");
    }

    /// A writer that blocks until a test lets it through, so a queue can be
    /// observed while it is still a queue.
    struct Stalled(mpsc::Receiver<()>, Arc<Mutex<Vec<u8>>>);

    impl Write for Stalled {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.0.recv().is_err() {
                return Err(std::io::Error::other("released"));
            }
            self.1.lock().expect("sink log").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn write_vectored(&mut self, frames: &[IoSlice<'_>]) -> std::io::Result<usize> {
            self.write(&gathered(frames))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn stalled() -> (AttachmentSink, mpsc::Sender<()>, Arc<Mutex<Vec<u8>>>) {
        let (tx, rx) = mpsc::channel();
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = AttachmentSink::new(Box::new(Stalled(rx, Arc::clone(&log))), Version::LOCAL)
            .expect("sink");
        (sink, tx, log)
    }

    /// The property mosh was built around and a FIFO of screens gives up: a
    /// client too slow to drain is never handed a state it is known to be
    /// behind.
    #[test]
    fn a_newer_screen_replaces_the_one_still_waiting() {
        let (sink, release, log) = stalled();
        for generation in 0..64_u8 {
            sink.send_screen(Cut::raw(vec![vec![generation; 8]]))
                .expect("screen");
        }
        // The stalled writer holds the first batch; everything after it
        // collapsed into one slot rather than sixty-four.
        assert!(!sink.is_drained());
        for _ in 0..4 {
            let _ = release.send(());
        }
        std::thread::sleep(Duration::from_millis(50));
        let written = log.lock().expect("sink log").clone();
        assert!(
            written.len() <= 16,
            "stale screens reached the wire: {written:?}"
        );
        assert_eq!(written.last(), Some(&63));
        sink.close();
    }

    /// A screen cut for a datagram is several frames that are one state, so the
    /// slot supersedes all of them together.
    #[test]
    fn a_newer_screen_replaces_every_piece_of_the_one_still_waiting() {
        let (sink, release, log) = stalled();
        sink.send_screen(Cut::raw(vec![vec![0xA0; 8], vec![0xA1; 8], vec![0xA2; 8]]))
            .expect("first screen");
        // Held inside the writer's `write`, so what follows is a queue rather
        // than a race with the drain.
        std::thread::sleep(Duration::from_millis(50));
        sink.send_screen(Cut::raw(vec![vec![0xB0; 8], vec![0xB1; 8]]))
            .expect("second screen");
        sink.send_screen(Cut::raw(vec![vec![0xC0; 8], vec![0xC1; 8]]))
            .expect("third screen");
        for _ in 0..4 {
            let _ = release.send(());
        }
        let written = wait_for(&log, 40);
        assert!(
            !written[24..].contains(&0xB0),
            "a superseded screen reached the wire: {written:?}"
        );
        assert_eq!(
            &written[24..40],
            [[0xC0; 8], [0xC1; 8]].concat().as_slice(),
            "the newest screen goes out whole"
        );
        sink.close();
    }

    /// Reserved room was never priority: an `Exit` at the back of the order
    /// waits out every stream frame in front of it.
    #[test]
    fn a_terminal_message_jumps_the_stream_it_supersedes() {
        let (sink, release, log) = stalled();
        sink.send_output(vec![0xAA; 8]).expect("first frame");
        // Let the writer take that one and park inside `write`.
        std::thread::sleep(Duration::from_millis(50));
        for _ in 0..8 {
            sink.send_output(vec![0xBB; 4096]).expect("stream frame");
        }
        sink.send(&ServerMessage::Exit { code: 0 }).expect("exit");
        for _ in 0..4 {
            let _ = release.send(());
        }
        let exit = exit_frame();
        let written = wait_for(&log, 8 + exit.len());
        assert_eq!(
            &written[8..8 + exit.len()],
            exit.as_slice(),
            "the exit queued behind the stream it supersedes"
        );
        sink.close();
    }

    /// The byte stream is bounded by bytes, and overrunning it starts a sync
    /// episode rather than something to wait on.
    #[test]
    fn the_stream_lane_refuses_rather_than_waits() {
        let (sink, release, _log) = stalled();
        let mut refused = false;
        for _ in 0..64 {
            if sink.send_output(vec![0; 16 * 1024]).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused, "an undrained stream lane must fill");
        // An exit refused because a flood filled the queue is a client that
        // never learns its shell died.
        sink.send(&ServerMessage::Exit { code: 0 })
            .expect("control messages have reserved room");
        let _ = release.send(());
        sink.close();
    }

    /// A discard drops the lane a screen makes dead and only that lane: the
    /// `Exit` stays because no screen says the shell is gone, and the screen
    /// stays because it is what the discard clears the way for.
    #[test]
    fn a_discard_drops_the_stream_and_keeps_what_no_screen_carries() {
        let (sink, release, log) = stalled();
        sink.send_output(vec![0xAA; 8]).expect("first frame");
        // Held inside the writer's `write`, so what follows is a queue rather
        // than a race with the drain.
        std::thread::sleep(Duration::from_millis(50));
        sink.send_screen(Cut::raw(vec![vec![0xC0; 8], vec![0xC1; 8]]))
            .expect("screen");
        for _ in 0..8 {
            sink.send_output(vec![0xBB; 4096]).expect("stream frame");
        }
        sink.send(&ServerMessage::Exit { code: 0 }).expect("exit");
        sink.discard_stream();
        for _ in 0..4 {
            let _ = release.send(());
        }
        let mut want = vec![0xAA_u8; 8];
        want.extend_from_slice(&exit_frame());
        want.extend_from_slice(&[0xC0; 8]);
        want.extend_from_slice(&[0xC1; 8]);
        let written = wait_for(&log, want.len());
        assert_eq!(
            written, want,
            "a discard takes the byte stream and nothing else"
        );
        sink.close();
    }

    /// The freed room is recomputed rather than zeroed: the reserved frames a
    /// discard keeps still occupy the lane the next `push` is measured against.
    #[test]
    fn a_discard_leaves_the_lane_measured_by_what_survived() {
        let (sink, release, _log) = stalled();
        sink.send_output(vec![0; 8]).expect("first frame");
        std::thread::sleep(Duration::from_millis(50));
        let mut refused = false;
        for _ in 0..64 {
            if sink.send_output(vec![0; 16 * 1024]).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused, "an undrained stream lane must fill");
        sink.send(&ServerMessage::Exit { code: 0 })
            .expect("control messages have reserved room");
        sink.send_screen(Cut::raw(vec![vec![0xC0; 8]]))
            .expect("screen");
        sink.discard_stream();
        {
            let queue = sink.shared().queue.lock().expect("queue");
            assert_eq!(
                queue.stream.queued,
                exit_frame().len(),
                "the surviving control frame still occupies the lane"
            );
            assert_eq!(queue.order.len(), 2, "the exit and the screen survived");
            assert_eq!(queue.pieces.len(), 1, "the screen's payload survived");
            assert!(
                !sink.is_drained(),
                "a queue the transport has not been handed is not drained"
            );
        }
        // Stale accounting would refuse this, which is the whole-screen mode
        // the discard exists to get the client out of.
        sink.send_output(vec![0; 16 * 1024])
            .expect("the discard returned the room the dropped output held");
        let _ = release.send(());
        sink.close();
    }

    /// A dead client must not look like a slow one: a writer that breaks out of
    /// its loop without closing the queue leaves `push` answering `Ok` until the
    /// budget overruns, which the actor reads as backpressure. A discard happens
    /// on the way into that mode, so it answers rather than panics.
    #[test]
    fn a_dead_writer_closes_the_queue_rather_than_filling_it() {
        let sink = AttachmentSink::new(Box::new(Refusing), Version::LOCAL).expect("sink");
        sink.send_output(vec![0; 16])
            .expect("the first frame queues");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !sink.is_closed() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(sink.is_closed(), "a failed write must close the queue");
        sink.discard_stream();
        assert!(
            !sink.is_drained(),
            "a client that is gone is not a client keeping up"
        );
        assert!(
            matches!(sink.send_output(vec![0; 16]), Err(SinkError::Unusable)),
            "a dead client must be refused, not throttled"
        );
    }

    /// Teardown is a property of ownership, and the sink is cloned, so it is the
    /// *last* clone that counts.
    #[test]
    fn the_last_clone_going_away_retires_the_writer() {
        let (tx, rx) = mpsc::channel();
        let sink = AttachmentSink::new(Box::new(Retiring(tx)), Version::LOCAL).expect("sink");
        let clone = sink.clone();
        drop(sink);
        assert!(
            rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "a surviving clone still has a client to serve"
        );
        drop(clone);
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the writer parks forever unless its last producer retires it");
    }

    /// `WouldBlock` is the one `io::Error` that does not mean the connection is
    /// over; reading it as one retires the attachment the first time a cwnd
    /// closes, which on a lossy link is immediately.
    #[test]
    fn a_transport_that_refuses_for_want_of_window_is_not_a_client_that_is_gone() {
        let (sink, log, admit) = congested();
        sink.send_output(vec![0xAA; 8]).expect("the frame queues");
        // Long enough for a writer that mistook this for a dead connection to
        // have retired itself.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!sink.is_closed(), "a closed window is not a closed socket");
        assert!(
            !sink.is_drained(),
            "bytes the window refused are bytes the client has not been given"
        );
        admit.store(usize::MAX, Ordering::Relaxed);
        assert_eq!(wait_for(&log, 8), vec![0xAA; 8]);
        sink.close();
    }

    /// `Ok(n)` means the transport took `n` bytes, and a retry that started over
    /// would put those `n` on the wire twice.
    #[test]
    fn a_partial_write_before_a_blocked_one_is_not_sent_again() {
        let (sink, log, admit) = congested();
        admit.store(3, Ordering::Relaxed);
        sink.send_output(b"abcdefghij".to_vec())
            .expect("the frame queues");
        assert_eq!(wait_for(&log, 3), b"abc".to_vec());
        admit.store(usize::MAX, Ordering::Relaxed);
        assert_eq!(wait_for(&log, 10), b"abcdefghij".to_vec());
        sink.close();
    }

    /// What the transport is offered after it stopped part way through.
    fn remainder_of(batch: &Batch) -> (usize, Vec<u8>) {
        let mut slices = [IoSlice::new(&[]); VECTORED];
        let (filled, _) = batch.remainder(&mut slices);
        (filled, gathered(&slices[..filled]))
    }

    /// A frame behind the resume point offered again is output duplicated, and
    /// a frame ahead of it skipped is output lost. Driven through `advance`
    /// rather than by setting `sent`: the cursor it keeps is what decides
    /// which frame the next offer starts at.
    #[test]
    fn the_remainder_of_a_partial_write_starts_where_the_transport_stopped() {
        let mut batch = Batch::new();
        batch.push(b"abcde".to_vec(), Coding::Raw);
        batch.push(b"fghij".to_vec(), Coding::Raw);
        assert_eq!(batch.owed, 10);
        assert_eq!(remainder_of(&batch), (2, b"abcdefghij".to_vec()));

        batch.advance(3);
        assert_eq!(remainder_of(&batch), (2, b"defghij".to_vec()));

        batch.advance(2);
        assert_eq!(
            remainder_of(&batch),
            (1, b"fghij".to_vec()),
            "a frame the transport finished is not offered a second time"
        );
        assert_eq!(batch.at, 1, "the cursor stepped past the frame that ended");

        batch.advance(2);
        assert_eq!(remainder_of(&batch), (1, b"hij".to_vec()));

        batch.advance(3);
        assert!(batch.is_spent());
        assert_eq!(remainder_of(&batch), (0, Vec::new()));
    }

    /// The whole reason the screen lane is one slot deep: a client waiting on a
    /// congestion window must not be handed a state it is known to be behind.
    #[test]
    fn a_screen_waiting_on_a_closed_window_is_still_superseded_by_a_newer_one() {
        let (sink, log, admit) = congested();
        // Taken into the batch and refused by the window, so what follows
        // queues behind a remainder the writer still owes.
        sink.send_output(vec![0xAA; 8]).expect("the frame queues");
        std::thread::sleep(Duration::from_millis(50));
        for generation in 0..32_u8 {
            sink.send_screen(Cut::raw(vec![vec![generation; 8]]))
                .expect("screens never fill the lane");
        }
        assert_eq!(
            sink.shared().queue.lock().expect("queue").order.len(),
            1,
            "thirty-two screens collapsed into one slot while the window was shut"
        );
        admit.store(usize::MAX, Ordering::Relaxed);
        assert_eq!(
            wait_for(&log, 16),
            [vec![0xAA; 8], vec![31; 8]].concat(),
            "only the newest screen followed the frame in flight"
        );
        sink.close();
    }

    /// Reported so the session can compose something smaller, never dropped,
    /// because the ledger has already planned against this screen being sent.
    #[test]
    fn an_oversized_screen_is_queued_and_reported_rather_than_dropped() {
        let (sink, release, _log) = stalled();
        assert_eq!(
            sink.send_screen(Cut::raw(vec![vec![0; 8]]))
                .expect("small screen"),
            ScreenPressure::Clear
        );
        // Wait for the writer to have *taken* that screen and parked inside the
        // stalled write. Until it has, `fill` can empty the queue between the
        // send below and the assertions, which moves the bytes from `queued` to
        // `taken` and leaves `pieces` empty — the counters are still right, but
        // neither one alone is stable enough to assert on. Once it is parked it
        // cannot fill again, so everything after this stays where it was put.
        let started = Instant::now();
        while !sink.shared().queue.lock().expect("queue").in_flight {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the writer never took the first screen"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            sink.send_screen(Cut::raw(vec![vec![0; SCREEN_LIMIT], vec![0; 1]]))
                .expect("a screen is never refused"),
            ScreenPressure::Over
        );
        {
            let queue = sink.shared().queue.lock().expect("queue");
            assert_eq!(queue.screen.queued, SCREEN_LIMIT + 1);
            assert_eq!(queue.pieces.len(), 2, "the screen is queued, not dropped");
        }
        let _ = release.send(());
        sink.close();
    }

    /// A batch the writer has taken is memory this attachment still owns.
    /// Counted only while it was queued, it let a second full lane in beside it
    /// - and [`CEILING`] is the number the daemon admits attachments against.
    #[test]
    fn a_batch_the_writer_is_holding_still_occupies_its_lane() {
        let (sink, release, _log) = stalled();
        sink.send_output(vec![0_u8; BATCH])
            .expect("the first chunk");
        let started = Instant::now();
        loop {
            {
                let queue = sink.shared().queue.lock().expect("queue");
                if queue.order.is_empty() && queue.in_flight {
                    assert_eq!(
                        queue.stream.charged(),
                        BATCH,
                        "the lane forgot the batch the writer is holding"
                    );
                    break;
                }
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "the writer never took the batch"
            );
            std::thread::yield_now();
        }

        let mut admitted = BATCH;
        while sink.send_output(vec![0_u8; BATCH]).is_ok() {
            admitted += BATCH;
            assert!(
                admitted <= STREAM_LIMIT,
                "{admitted} bytes are queued or in flight against a {STREAM_LIMIT}-byte lane"
            );
        }
        let _ = release.send(());
        sink.close();
    }

    /// A transport with a congestion window: it takes `admit` bytes per call
    /// and answers `WouldBlock` once that allowance is spent.
    struct Congested {
        log: Arc<Mutex<Vec<u8>>>,
        admit: Arc<AtomicUsize>,
    }

    impl Write for Congested {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let allowance = self.admit.load(Ordering::Relaxed);
            if allowance == 0 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let taken = allowance.min(buf.len());
            self.log.lock().expect("sink log").extend(&buf[..taken]);
            // `usize::MAX` is a window a test has opened for good.
            if allowance != usize::MAX {
                self.admit.store(allowance - taken, Ordering::Relaxed);
            }
            Ok(taken)
        }

        fn write_vectored(&mut self, frames: &[IoSlice<'_>]) -> io::Result<usize> {
            self.write(&gathered(frames))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn congested() -> (AttachmentSink, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let admit = Arc::new(AtomicUsize::new(0));
        let sink = AttachmentSink::new(
            Box::new(Congested {
                log: Arc::clone(&log),
                admit: Arc::clone(&admit),
            }),
            Version::LOCAL,
        )
        .expect("sink");
        (sink, log, admit)
    }

    /// A screen supersedes the byte stream and nothing else: a client throwing
    /// forwarded bytes away on arrival is a `-L` tunnel silently corrupted by a
    /// sync episode on the terminal beside it.
    #[test]
    fn a_discard_takes_the_byte_stream_and_leaves_the_forward_payload() {
        let (sink, log, admit) = congested();
        // A frame that fills a whole batch by itself: whatever the writer's
        // timing, its one `fill` against a window taking nothing stops here, so
        // the two frames behind it are still in the order to be discarded - and
        // if it has not run at all, they are too.
        sink.send_output(vec![0xEE; BATCH]).expect("a first frame");
        sink.send_output(vec![0xAA; 16])
            .expect("byte-stream output");
        sink.send_forward(vec![0xBB; 16]).expect("forward payload");

        sink.discard_stream();
        admit.store(usize::MAX, Ordering::Relaxed);

        // The forward frame is last in the order, so everything that survived
        // the discard has gone out by the time it has.
        let deadline = Instant::now() + Duration::from_secs(5);
        let written = loop {
            let written = log.lock().expect("sink log").clone();
            if written.windows(16).any(|window| window == [0xBB; 16]) {
                break written;
            }
            assert!(
                Instant::now() < deadline,
                "the discard ate a forwarded connection's payload"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(
            !written.windows(16).any(|window| window == [0xAA; 16]),
            "the byte stream a screen supersedes was not discarded"
        );
        sink.close();
    }

    /// `outstanding` is what `gate::may_return_to_passthrough` ends up asking.
    /// Forward payload says nothing about whether this client is keeping up with
    /// its *terminal*: counted here, a busy tunnel reads as a stalled terminal
    /// and pins the session in sync mode for as long as the tunnel is busy.
    #[test]
    fn forward_payload_is_not_output_the_client_has_failed_to_take() {
        let (sink, _log, _admit) = congested();
        sink.send_output(vec![0xEE; BATCH]).expect("a first frame");
        // One frame, either still queued or already in the writer's batch: the
        // two are the same number here, which is what makes this test
        // independent of when the writer ran.
        let stalled = sink.shared().outstanding.load(Ordering::Relaxed);
        assert_eq!(stalled, 1);

        for _ in 0..4 {
            sink.send_forward(vec![0xBB; 4096])
                .expect("forward payload");
        }
        assert_eq!(
            sink.shared().queue.lock().expect("queue").forward_entries,
            4,
            "the forward lane is not counting its own entries"
        );
        assert_eq!(
            sink.shared().outstanding.load(Ordering::Relaxed),
            stalled,
            "a busy tunnel reads as a terminal that has stopped draining"
        );

        sink.send_output(vec![0xAA; 16])
            .expect("byte-stream output");
        assert_eq!(
            sink.shared().outstanding.load(Ordering::Relaxed),
            stalled + 1,
            "the byte stream itself must still be counted"
        );
        sink.close();
    }
}
