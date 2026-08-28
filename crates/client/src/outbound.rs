#![forbid(unsafe_code)]

//! The sending half: carriage, the journal's debt, and where typing waits.

use crate::dgram::DatagramSink;
use crate::journal::{CommandJournal, Deferred, JournalError};
use crate::state::{ReconnectState, load_sessions, save_sessions, sweep_staging};
use crate::transport::Outbox;
use crate::{ClientError, JOURNAL_CAPACITY, MAX_PENDING_INPUT};
use braid_proto::{
    ByteOff, ClientMessage, CmdSeq, ForwardTarget, Generation, GridSize, MAX_FORWARD_CHUNK,
    MAX_INPUT_CHUNK, MIN_DATAGRAM_FRAME, ScreenVersion, StreamId, Version,
};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// A stream is already ordered and already retransmits; a datagram is neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Carriage {
    Stream,
    Datagram,
}

/// `Input` beside its bytes: length prefix, tag, sequence, byte count.
const INPUT_OVERHEAD: usize = 4 + 1 + 8 + 4;

/// `ForwardData` beside its bytes: length prefix, tag, stream, offset, flag,
/// byte count. The prefix is counted on the datagram path too, then stripped.
const FORWARD_OVERHEAD: usize = 4 + 1 + 4 + 8 + 1 + 4;

impl Carriage {
    /// Nothing fragments on the datagram path: an oversized chunk cannot seal.
    const fn input_chunk(self) -> usize {
        match self {
            Self::Stream => MAX_INPUT_CHUNK,
            Self::Datagram => MIN_DATAGRAM_FRAME - INPUT_OVERHEAD,
        }
    }

    const fn forward_chunk(self) -> usize {
        match self {
            Self::Stream => MAX_FORWARD_CHUNK,
            Self::Datagram => MIN_DATAGRAM_FRAME - FORWARD_OVERHEAD,
        }
    }
}

/// A trait rather than a `Write` so this never blocks on the transport while
/// holding the lock the rest of the client needs; `false` is a link that is
/// not draining, and the journal holds the message until a reconnect replays.
pub(crate) trait FrameSink {
    fn carriage(&self) -> Carriage;

    fn send(&self, frame: Vec<u8>) -> bool;

    /// A `Close` refused because a paste is in front of it leaves the remote
    /// shell running, so it draws on room reserved for exactly that.
    fn send_reserved(&self, frame: Vec<u8>) -> bool {
        self.send(frame)
    }
}

impl FrameSink for Outbox {
    fn carriage(&self) -> Carriage {
        Carriage::Stream
    }

    fn send(&self, frame: Vec<u8>) -> bool {
        Self::send(self, frame)
    }

    fn send_reserved(&self, frame: Vec<u8>) -> bool {
        Self::send_reserved(self, frame)
    }
}

/// The journal and its acks are the same either way, which makes an
/// ssh-to-datagram migration a sink swap rather than a second client.
pub(crate) enum Link {
    Ssh(Outbox),
    Datagram(DatagramSink),
}

impl FrameSink for Link {
    fn carriage(&self) -> Carriage {
        match self {
            Self::Ssh(outbox) => outbox.carriage(),
            Self::Datagram(sink) => sink.carriage(),
        }
    }

    fn send(&self, frame: Vec<u8>) -> bool {
        match self {
            Self::Ssh(outbox) => outbox.send(frame),
            Self::Datagram(sink) => sink.send(frame),
        }
    }

    fn send_reserved(&self, frame: Vec<u8>) -> bool {
        match self {
            Self::Ssh(outbox) => outbox.send_reserved(frame),
            Self::Datagram(sink) => sink.send_reserved(frame),
        }
    }
}

/// Sequence numbers are allocated when a message reaches a transport, never
/// when input is produced: numbering untransmittable bytes lets a user typing
/// through a disconnect exhaust the journal and lose a recoverable session.
pub(crate) struct ClientWriter<W> {
    pub(crate) state: Mutex<Outbound<W>>,
    pub(crate) close_requested: AtomicBool,
    /// The status line is the only report that a keystroke was thrown away.
    pub(crate) dropped_input: AtomicBool,
    /// Suppresses a repaint storm: each request costs a server generation and
    /// a full screen, so one lost datagram must not ask once per frame behind.
    repaint_outstanding: AtomicBool,
    /// Counted up on every sink change, so a resend thread waking after an
    /// upgrade does not retransmit against a link that is no longer current.
    link_epoch: AtomicU64,
}

pub(crate) struct Outbound<W> {
    /// `None` while no transport can carry anything.
    pub(crate) output: Option<W>,
    pub(crate) next_seq: CmdSeq,
    pub(crate) journal: CommandJournal,
    /// Input waiting for a transport, in the order it was typed.
    pub(crate) pending: Vec<u8>,
    /// Control messages a full journal could not number yet.
    pub(crate) deferred: Deferred,
    pub(crate) resend: Resend,
    /// Refilled rather than reallocated: a single typed byte would otherwise
    /// cost a heap allocation.
    pub(crate) spare: Vec<u8>,
    /// The journal holds messages rather than frames, so a reconnect
    /// re-encodes at the new link's version.
    pub(crate) version: Version,
}

/// Nothing here runs on a stream: a client retransmitting behind TCP is waste.
#[derive(Default)]
pub(crate) struct Resend {
    /// Smoothed round trip at one eighth, as TCP does. `None` until sampled.
    pub(crate) srtt: Option<Duration>,
    /// Dropped without a sample when resent — a sample from a retransmission
    /// cannot say which copy was acknowledged. Karn's algorithm.
    sample: Option<(CmdSeq, Instant)>,
    waiting: Option<Instant>,
    /// Consecutive resends with nothing acknowledged.
    attempts: u32,
    acked: Option<CmdSeq>,
    /// One fast retransmit per stalled ack; the timer covers a lost one.
    retried: bool,
}

/// A cumulative ack cannot advance past the oldest thing the server is
/// missing, so a repeat over a non-empty journal says the front is lost —
/// 600 ms sooner than the two-round-trip timer learns it at 300 ms RTT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    /// It moved: what was outstanding has landed.
    Advanced,
    /// It repeated, and this is the first repeat since it last moved.
    Stalled,
    /// It repeated again, and the front has already gone out for it.
    Repeated,
}

pub(crate) const INITIAL_RESEND: Duration = Duration::from_millis(250);

/// The floor stops a microsecond-latency link from multiplying keystrokes; the
/// ceiling stops a dead link from outwaiting the read deadline.
pub(crate) const MIN_RESEND: Duration = Duration::from_millis(50);
const MAX_RESEND: Duration = Duration::from_secs(2);

/// The front is what unblocks a cumulative ack; the bound stops a stalled link
/// re-sending a full journal every interval.
const RESEND_BATCH: usize = 4;

impl Resend {
    /// Two round trips, doubling for every resend nothing answered.
    fn interval(&self) -> Duration {
        let base = self
            .srtt
            .map_or(INITIAL_RESEND, |srtt| srtt.saturating_mul(2));
        base.saturating_mul(1_u32 << self.attempts.min(5))
            .clamp(MIN_RESEND, MAX_RESEND)
    }

    /// `timed` is a sequence a round trip may be measured from: only `Input`.
    pub(crate) fn transmitted(&mut self, timed: Option<CmdSeq>, now: Instant) {
        self.waiting.get_or_insert(now);
        if let Some(sequence) = timed
            && self.sample.is_none()
        {
            self.sample = Some((sequence, now));
        }
    }

    pub(crate) fn acknowledged(&mut self, highest: CmdSeq, now: Instant) -> Progress {
        if let Some((sequence, sent)) = self.sample
            && sequence <= highest
        {
            self.observe(now.saturating_duration_since(sent));
            self.sample = None;
        }
        if self.acked < Some(highest) {
            self.acked = Some(highest);
            self.attempts = 0;
            self.waiting = None;
            self.retried = false;
            return Progress::Advanced;
        }
        // The wait is deliberately not restarted for an ack that said nothing
        // new: that would push the deadline out ahead of itself forever.
        if std::mem::replace(&mut self.retried, true) {
            Progress::Repeated
        } else {
            Progress::Stalled
        }
    }

    fn observe(&mut self, sample: Duration) {
        self.srtt = Some(match self.srtt {
            None => sample,
            Some(srtt) => (srtt * 7 + sample) / 8,
        });
    }

    /// Whether the front is owed another copy, starting the next wait when so.
    pub(crate) fn due(&mut self, now: Instant) -> bool {
        let waiting = *self.waiting.get_or_insert(now);
        if now.saturating_duration_since(waiting) < self.interval() {
            return false;
        }
        self.attempts = self.attempts.saturating_add(1);
        self.waiting = Some(now);
        true
    }

    /// A message this side has now sent twice can measure nothing.
    fn resent(&mut self, highest: CmdSeq) {
        if self.sample.is_some_and(|(sequence, _)| sequence <= highest) {
            self.sample = None;
        }
    }

    fn remaining(&self, now: Instant) -> Duration {
        let waited = self
            .waiting
            .map_or(Duration::ZERO, |since| now.saturating_duration_since(since));
        self.interval().saturating_sub(waited)
    }
}

impl<W: FrameSink> Outbound<W> {
    fn send<F>(&mut self, make_message: F) -> Result<Option<CmdSeq>, JournalError>
    where
        F: FnOnce(CmdSeq) -> ClientMessage,
    {
        if self.journal.is_full() {
            return Err(JournalError::Full);
        }
        Ok(self.queue(make_message))
    }

    /// Send a command nothing is replayed after: displacing the oldest entry
    /// punches a gap the server's gate refuses, harmless only for the last.
    fn send_terminal<F>(&mut self, make_message: F)
    where
        F: FnOnce(CmdSeq) -> ClientMessage,
    {
        if self.journal.is_full() {
            self.journal.displace_oldest();
        }
        let _ = self.queue_with(true, make_message);
    }

    pub(crate) fn queue<F>(&mut self, make_message: F) -> Option<CmdSeq>
    where
        F: FnOnce(CmdSeq) -> ClientMessage,
    {
        self.queue_with(false, make_message)
    }

    /// `None` when the message was never numbered, so nothing can acknowledge
    /// it and nothing predicted against it may ever be released.
    fn queue_with<F>(&mut self, reserved: bool, make_message: F) -> Option<CmdSeq>
    where
        F: FnOnce(CmdSeq) -> ClientMessage,
    {
        let sequence = self.next_seq;
        let message = make_message(sequence);
        // Only an `Input` is worth timing: its ack is the round trip measured.
        let timed = matches!(message, ClientMessage::Input { .. }).then_some(sequence);
        let Ok(encoded) = message.encode(self.version) else {
            return None;
        };
        // A number given to a message that is not retained is a gap the
        // server's gate drops the attachment for.
        if self.journal.push(sequence, message).is_err() {
            return None;
        }
        self.next_seq = sequence.next();
        let Some(output) = self.output.as_ref() else {
            return Some(sequence);
        };
        let carriage = output.carriage();
        let queued = if reserved {
            output.send_reserved(encoded)
        } else {
            output.send(encoded)
        };
        if !queued {
            // Dropping the sink is what turns a stalled transport into the
            // reconnect that replays this message.
            self.output = None;
            return Some(sequence);
        }
        if carriage == Carriage::Datagram {
            self.resend.transmitted(timed, Instant::now());
        }
        Some(sequence)
    }

    fn carriage(&self) -> Option<Carriage> {
        self.output.as_ref().map(FrameSink::carriage)
    }

    fn resend_front(&mut self) {
        let mut highest = None;
        for (sequence, message) in self.journal.oldest(RESEND_BATCH) {
            let Ok(encoded) = message.encode(self.version) else {
                continue;
            };
            let Some(output) = self.output.as_ref() else {
                break;
            };
            if !output.send(encoded) {
                self.output = None;
                break;
            }
            highest = Some(sequence);
        }
        if let Some(highest) = highest {
            self.resend.resent(highest);
        }
    }

    /// Control first: a resize describes the grid the pending keystrokes were
    /// typed into. Reports the sequence the last of that input took.
    fn drain(&mut self) -> Option<CmdSeq> {
        let chunk = self.output.as_ref()?.carriage().input_chunk();
        if let Some(size) = self.deferred.resize
            && self.send(|seq| ClientMessage::Resize { seq, size }).is_ok()
        {
            self.deferred.resize = None;
        }
        if self.deferred.repaint
            && self
                .send(|seq| ClientMessage::RequestRepaint { seq })
                .is_ok()
        {
            self.deferred.repaint = false;
        }
        let mut sent = 0;
        let mut last = None;
        while sent < self.pending.len() {
            let end = (sent + chunk).min(self.pending.len());
            let mut bytes = std::mem::take(&mut self.spare);
            bytes.clear();
            bytes.extend_from_slice(&self.pending[sent..end]);
            let Ok(sequence) = self.send(|seq| ClientMessage::Input { seq, bytes }) else {
                break;
            };
            if sequence.is_some() {
                last = sequence;
            }
            sent = end;
        }
        self.pending.drain(..sent);
        last
    }
}

/// `None` is input still pending, which the server has not seen and can never
/// acknowledge — so it must not be predicted on screen either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Accepted {
    /// Every byte is queued for the session.
    All(Option<CmdSeq>),
    /// The pending buffer is full; this many bytes were taken from the front.
    Partial { queued: usize, seq: Option<CmdSeq> },
}

impl<W: FrameSink> ClientWriter<W> {
    pub(crate) fn new(output: W, first_seq: CmdSeq, version: Version) -> Self {
        Self {
            state: Mutex::new(Outbound {
                output: Some(output),
                next_seq: first_seq,
                version,
                journal: CommandJournal::new(JOURNAL_CAPACITY),
                pending: Vec::new(),
                deferred: Deferred::default(),
                resend: Resend::default(),
                spare: Vec::new(),
            }),
            close_requested: AtomicBool::new(false),
            dropped_input: AtomicBool::new(false),
            repaint_outstanding: AtomicBool::new(false),
            link_epoch: AtomicU64::new(0),
        }
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Outbound<W>>, ClientError> {
        self.state
            .lock()
            .map_err(|_| ClientError::Io(io::Error::other("client output lock poisoned")))
    }

    /// Which link a thread that is about to run alongside this one belongs to.
    pub(crate) fn epoch(&self) -> u64 {
        self.link_epoch.load(Ordering::Acquire)
    }

    /// Clearing `dropped_input` matters: left set, one overrun makes every
    /// later disconnect claim lost typing that was in fact delivered.
    fn drain(&self, state: &mut Outbound<W>) -> Option<CmdSeq> {
        let last = state.drain();
        if state.pending.is_empty() {
            self.dropped_input.store(false, Ordering::Release);
        }
        last
    }

    pub(crate) fn input(&self, bytes: &[u8]) -> Result<Accepted, ClientError> {
        let mut state = self.lock()?;
        let room = MAX_PENDING_INPUT.saturating_sub(state.pending.len());
        let queued = room.min(bytes.len());
        state.pending.extend_from_slice(&bytes[..queued]);
        let last = self.drain(&mut state);
        // A sequence covers this typing only if every byte went out under one.
        let seq = if state.pending.is_empty() { last } else { None };
        Ok(if queued == bytes.len() {
            Accepted::All(seq)
        } else {
            self.dropped_input.store(true, Ordering::Release);
            Accepted::Partial { queued, seq }
        })
    }

    /// The transport is gone; hold everything until a replacement arrives.
    pub(crate) fn disconnect(&self) -> Result<(), ClientError> {
        // Bumped beneath the lock `retransmit` reads it under: a resend caller
        // blocked here must not come through believing it is current.
        let mut state = self.lock()?;
        state.output = None;
        self.link_epoch.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Install a replacement transport, replay what is unacknowledged, then
    /// release the input that accumulated while there was nowhere to put it.
    pub(crate) fn reconnect(&self, output: W, version: Version) -> Result<(), ClientError> {
        let mut state = self.lock()?;
        state.output = Some(output);
        state.version = version;
        // A replacement transport has measured nothing.
        state.resend = Resend::default();
        for message in state.journal.all() {
            let encoded = message.encode(state.version)?;
            // Reserved room: replay is exactly what it is kept for.
            if let Some(output) = state.output.as_ref()
                && !output.send_reserved(encoded)
            {
                state.output = None;
                break;
            }
        }
        let _ = self.drain(&mut state);
        self.link_epoch.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Start over in the sequence space of a session that has never seen this
    /// client: it gates from [`CmdSeq::first`], so replaying the journal would
    /// number past the gate and stall behind a command nothing will apply.
    pub(crate) fn reopen(&self, output: W, version: Version) -> Result<(), ClientError> {
        let mut state = self.lock()?;
        state.output = Some(output);
        state.version = version;
        state.next_seq = CmdSeq::first();
        state.journal = CommandJournal::new(JOURNAL_CAPACITY);
        state.pending.clear();
        state.deferred = Deferred::default();
        state.resend = Resend::default();
        self.dropped_input.store(false, Ordering::Release);
        self.link_epoch.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Put the oldest unacknowledged commands back on the wire, and report
    /// when to look again. `None` is a caller with nothing left to do: a
    /// stream, or a link replaced since the caller was spawned for it.
    pub(crate) fn retransmit(
        &self,
        now: Instant,
        epoch: u64,
    ) -> Result<Option<Duration>, ClientError> {
        let mut state = self.lock()?;
        if self.epoch() != epoch || state.carriage() != Some(Carriage::Datagram) {
            return Ok(None);
        }
        if state.journal.is_empty() {
            state.resend.waiting = None;
            return Ok(Some(state.resend.interval()));
        }
        if state.resend.due(now) {
            state.resend_front();
        }
        Ok(Some(state.resend.remaining(now)))
    }

    pub(crate) fn request_repaint(&self) -> Result<(), ClientError> {
        // The screen a request in flight will bring answers this one too.
        if self.repaint_outstanding.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut state = self.lock()?;
        if state
            .send(|seq| ClientMessage::RequestRepaint { seq })
            .is_err()
        {
            state.deferred.repaint = true;
        }
        Ok(())
    }

    pub(crate) fn repaint_arrived(&self) {
        self.repaint_outstanding.store(false, Ordering::Release);
    }

    /// Moving the receive window only on a `Pong` caps datagram passthrough at
    /// roughly a megabyte a second. Unsequenced; the server keeps the largest.
    pub(crate) fn consumed(&self, off: ByteOff) -> Result<(), ClientError> {
        let state = self.lock()?;
        if let Some(output) = state.output.as_ref() {
            let _ = output.send_reserved(ClientMessage::Consumed { off }.encode(state.version)?);
        }
        Ok(())
    }

    /// Unsequenced and unjournalled: idempotent state, and a dropped one costs
    /// nothing because the next screen brings another.
    pub(crate) fn screen_ack(
        &self,
        generation: Generation,
        version: ScreenVersion,
    ) -> Result<(), ClientError> {
        let state = self.lock()?;
        if let Some(output) = state.output.as_ref() {
            let _ = output.send(
                ClientMessage::ScreenAck {
                    generation,
                    version,
                }
                .encode(state.version)?,
            );
        }
        Ok(())
    }

    pub(crate) fn resize(&self, size: GridSize) -> Result<(), ClientError> {
        let mut state = self.lock()?;
        if state
            .send(|seq| ClientMessage::Resize { seq, size })
            .is_err()
        {
            state.deferred.resize = Some(size);
        }
        Ok(())
    }

    /// Must arrive exactly once — a second copy under the same stream is a
    /// second socket nothing ever closes — so it is journalled and replayed. A
    /// full journal refuses rather than defers; the caller closes the socket.
    pub(crate) fn forward_open(
        &self,
        stream: StreamId,
        target: ForwardTarget,
    ) -> Result<(), ClientError> {
        let mut state = self.lock()?;
        match state.send(|seq| ClientMessage::ForwardOpen {
            seq,
            stream,
            target,
        }) {
            Ok(Some(_)) => Ok(()),
            // `Ok(None)` was never numbered: same outcome as a refusal.
            Ok(None) | Err(_) => Err(ClientError::Io(io::Error::other(
                "no room to open a forwarded connection",
            ))),
        }
    }

    /// Unsequenced by design: a `CmdSeq` would put forwarded payload in the
    /// ordered command stream, where one lost frame holds every keystroke
    /// behind its retransmission; [`braid_forward`] owes these by offset
    /// instead. `send` and never `send_reserved` — the reserved room is what a
    /// `Close` is drawn from. A refusal is backpressure, so the link stands.
    pub(crate) fn forward_frame(&self, message: &ClientMessage) -> Result<bool, ClientError> {
        // Encoded under the lock that installs the version, so a reconnect
        // cannot land a frame on a link that agreed a different one.
        let state = self.lock()?;
        let encoded = message.encode(state.version)?;
        let Some(output) = state.output.as_ref() else {
            return Ok(false);
        };
        Ok(output.send(encoded))
    }

    /// `None` while nothing can carry one, so the caller skips the pass rather
    /// than building a segment whose only outcome is a refusal.
    pub(crate) fn forward_chunk(&self) -> Result<Option<usize>, ClientError> {
        Ok(self.lock()?.carriage().map(Carriage::forward_chunk))
    }

    /// The flag goes up *before* the frame goes out. It records that the user
    /// asked, which is true at this call and not at the store after it: the
    /// server can answer a `Close` with `Exit` faster than this thread reaches
    /// a store placed second, and the session loop then reads a shell that was
    /// asked to end as one that failed.
    pub(crate) fn close(&self) -> Result<(), ClientError> {
        self.close_requested.store(true, Ordering::Release);
        self.lock()?
            .send_terminal(|seq| ClientMessage::Close { seq });
        Ok(())
    }

    /// Sets the same suppression flag as [`Self::close`], in the same order and
    /// for the same reason: the transport ending after this is expected, not a
    /// failure to reconnect from.
    pub(crate) fn detach(&self) -> Result<(), ClientError> {
        self.close_requested.store(true, Ordering::Release);
        self.lock()?
            .send_terminal(|seq| ClientMessage::Detach { seq });
        Ok(())
    }

    pub(crate) fn acknowledge(&self, highest: CmdSeq) -> Result<(), ClientError> {
        let mut state = self.lock()?;
        if let Some(spare) = state.journal.acknowledge(highest) {
            state.spare = spare;
        }
        if state.carriage() == Some(Carriage::Datagram) {
            // Bound rather than left as a scrutinee: the borrow of `resend`
            // would otherwise still be live over the arm that resends.
            let progress = state.resend.acknowledged(highest, Instant::now());
            match progress {
                // Still missing the front, the one thing that unblocks an ack.
                Progress::Stalled => state.resend_front(),
                Progress::Advanced | Progress::Repeated => {}
            }
        }
        let _ = self.drain(&mut state);
        Ok(())
    }

    /// `None` on a stream, which measures nothing and leaves the gate open.
    pub(crate) fn srtt(&self) -> Result<Option<Duration>, ClientError> {
        Ok(self.lock()?.resend.srtt)
    }

    /// Unsequenced and unjournalled: a probe answered a reconnect later has
    /// measured the reconnect. `consumed` is the receive window, which on a
    /// datagram is the only thing stopping a flood at a terminal.
    pub(crate) fn pong(&self, token: u64, consumed: ByteOff) -> Result<(), ClientError> {
        let state = self.lock()?;
        if let Some(output) = state.output.as_ref() {
            let _ = output
                .send_reserved(ClientMessage::Pong { token, consumed }.encode(state.version)?);
        }
        Ok(())
    }
}

/// Throttled: the checkpoint only has to be recent enough to replay from a
/// still-buffered offset, and each write costs about 11us in the display path.
/// A `None` path is a process with no private directory — the session runs,
/// but a client killed under it cannot resume.
pub(crate) struct Checkpoint {
    pub(crate) path: Option<PathBuf>,
    last_write: Instant,
    /// Kept so writing this session's position does not forget them.
    pub(crate) others: Vec<ReconnectState>,
}

impl Checkpoint {
    const INTERVAL: Duration = Duration::from_millis(250);

    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        if let Some(path) = path.as_deref() {
            sweep_staging(path);
        }
        Self {
            path,
            last_write: Instant::now()
                .checked_sub(Self::INTERVAL)
                .unwrap_or_else(Instant::now),
            others: Vec::new(),
        }
    }

    /// The write ends in `fsync`, milliseconds on a busy disk, so the session
    /// loop hands the terminal what it is holding rather than parking behind.
    pub(crate) fn due(&self) -> bool {
        self.path.is_some() && self.last_write.elapsed() >= Self::INTERVAL
    }

    pub(crate) fn note(&mut self, state: &ReconnectState) {
        if self.last_write.elapsed() < Self::INTERVAL {
            return;
        }
        self.force(state);
    }

    /// Resuming is an optimisation and the session is not, so a failure
    /// reports once and stops trying.
    pub(crate) fn force(&mut self, state: &ReconnectState) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        // Newest first: the session this client is running is the one the next
        // bare `brd <destination>` should reattach to.
        let mut sessions = Vec::with_capacity(self.others.len() + 1);
        sessions.push(*state);
        sessions.extend_from_slice(&self.others);
        match save_sessions(path, &sessions) {
            Ok(()) => self.last_write = Instant::now(),
            Err(error) => {
                eprintln!("[brd] no resume state: {error}");
                self.path = None;
            }
        }
    }

    pub(crate) fn load(&self) -> io::Result<Vec<ReconnectState>> {
        self.path
            .as_deref()
            .map_or_else(|| Ok(Vec::new()), load_sessions)
    }
}
