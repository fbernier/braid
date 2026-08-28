#![forbid(unsafe_code)]

//! One attached client: everything a session keeps per screen rather than per
//! PTY, because two clients on two links fall behind independently.

use crate::actor::next_deadline;
use crate::defer::{DeferMark, DeferredOsc};
use crate::gate;
use crate::link::LinkTiming;
use crate::registry::AttachmentSlot;
use crate::screen::{self, ScreenLedger};
use crate::sink::{self, AttachmentSink, Coding, Cut, SinkError};
use crate::{
    AttachmentId, ECHO_HISTORY, ECHO_TIMEOUT, FRAME_LENGTH_PREFIX, HEADER_SLOP, OUTPUT_OVERHEAD,
    dgram, log::log,
};
use braid_proto::wire::pack_from;
use braid_proto::{
    ByteOff, ClientId, CmdSeq, EncodeError, Generation, GridSize, InputCue, MAX_FRAME,
    MAX_OUTPUT_CHUNK, RowUpdate, ScreenHeader, ScreenVersion, encode_output_into,
    encode_screen_parts,
};
use braid_vt::RepaintFrame;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// What bounds one message to this client. A handle rather than a number on a
/// datagram: the transport searches the path MTU while the session runs.
#[derive(Clone, Debug)]
pub(crate) enum Framing {
    Stream,
    Datagram { budget: dgram::PayloadLimit },
}

impl Framing {
    /// Bytes one frame to this client may occupy, length prefix included.
    pub(crate) fn frame_budget(&self) -> usize {
        match self {
            Self::Stream => MAX_OUTPUT_CHUNK,
            Self::Datagram { budget } => budget.get(),
        }
    }

    pub(crate) fn output_chunk(&self) -> usize {
        self.frame_budget() - OUTPUT_OVERHEAD
    }

    /// Bytes one screen piece may occupy: the largest frame this protocol
    /// carries, not the deliberately small [`Self::frame_budget`].
    fn screen_budget(&self) -> usize {
        match self {
            Self::Stream => MAX_FRAME as usize,
            Self::Datagram { budget } => budget.get(),
        }
    }

    pub(crate) fn packing(&self) -> Packing {
        match self {
            Self::Stream => Packing::Exact,
            Self::Datagram { .. } => Packing::Packed(Packed::new()),
        }
    }

    /// Bytes of deferred OSC sequences one screen may carry: they ride in the
    /// header, which travels in the `Head` piece alone, so one piece bounds them.
    fn deferred_budget(&self) -> usize {
        self.screen_budget()
            .saturating_sub(braid_proto::MAX_TITLE + HEADER_SLOP)
    }
}

/// Outcome of matching a client command against the session's sequence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// First delivery; apply it.
    Fresh,
    /// Already applied under an earlier attachment; acknowledge only.
    Duplicate,
    /// A command was lost, so the ordered stream cannot be reconstructed.
    Gap,
}

/// The session's position in the client's command sequence: a replay must be
/// acknowledged without being applied twice, a gap made visible not skipped.
struct CommandGate {
    pub(crate) next: CmdSeq,
}

impl CommandGate {
    pub(crate) const fn new() -> Self {
        Self {
            next: CmdSeq::first(),
        }
    }

    /// Whether a command may be applied, without consuming its number: a side
    /// effect that fails after the gate advanced loses that keystroke silently.
    pub(crate) const fn check(&self, seq: CmdSeq) -> Admission {
        if seq.get() == self.next.get() {
            return Admission::Fresh;
        }
        if seq.get() < self.next.get() {
            return Admission::Duplicate;
        }
        Admission::Gap
    }

    /// Consume the number [`Self::check`] just called `Fresh`.
    pub(crate) fn commit(&mut self) {
        self.next = self.next.next();
    }

    pub(crate) fn admit(&mut self, seq: CmdSeq) -> Admission {
        let admission = self.check(seq);
        if admission == Admission::Fresh {
            self.commit();
        }
        admission
    }
}

/// Commands the application has been given, and when: a sequence is published
/// once it has been in front of the application for [`ECHO_TIMEOUT`].
struct EchoAck {
    /// Bounded ring; only a paste storm inside one 50 ms window could fill it.
    pub(crate) pending: VecDeque<(CmdSeq, Instant)>,
    pub(crate) published: Option<CmdSeq>,
}

impl EchoAck {
    pub(crate) fn new() -> Self {
        Self {
            pending: VecDeque::with_capacity(ECHO_HISTORY),
            published: None,
        }
    }

    pub(crate) fn recorded(&mut self, seq: CmdSeq, at: Instant) {
        if self.pending.len() == ECHO_HISTORY {
            // Publishing a sequence the application has not had would release
            // a prediction that is still speculative.
            self.pending.pop_front();
        }
        self.pending.push_back((seq, at));
    }

    /// The newest sequence the application has had long enough to echo.
    pub(crate) fn published(&mut self, now: Instant) -> Option<CmdSeq> {
        while let Some(&(seq, at)) = self.pending.front() {
            if now.saturating_duration_since(at) < ECHO_TIMEOUT {
                break;
            }
            self.pending.pop_front();
            self.published = Some(seq);
        }
        self.published
    }
}

/// One client's place in the ordered command stream, which outlives its
/// transport: a resume replays commands under the numbers first sent, and two
/// clients sharing a session number theirs independently.
pub(crate) struct ClientStream {
    pub(crate) client: ClientId,
    gate: CommandGate,
    highest_command: Option<CmdSeq>,
    echo: EchoAck,
}

impl ClientStream {
    pub(crate) fn new(client: ClientId) -> Self {
        Self {
            client,
            gate: CommandGate::new(),
            highest_command: None,
            echo: EchoAck::new(),
        }
    }

    pub(crate) const fn check(&self, seq: CmdSeq) -> Admission {
        self.gate.check(seq)
    }

    /// Admit a command that has nothing able to fail behind it.
    pub(crate) fn admit(&mut self, seq: CmdSeq) -> Admission {
        self.gate.admit(seq)
    }

    /// Consume the number [`Self::check`] called `Fresh`, and start its echo
    /// clock: a gate advanced without the clock releases a stale prediction.
    pub(crate) fn applied(&mut self, seq: CmdSeq, at: Instant) {
        self.gate.commit();
        self.echo.recorded(seq, at);
    }

    /// The newest sequence the application has had long enough to echo.
    pub(crate) fn echo_ack(&mut self, now: Instant) -> Option<CmdSeq> {
        self.echo.published(now)
    }

    pub(crate) fn acknowledged(&mut self, seq: CmdSeq) -> Option<CmdSeq> {
        if self.highest_command.is_none_or(|highest| seq > highest) {
            self.highest_command = Some(seq);
        }
        self.highest_command
    }

    /// What a resuming client is told it has already had acknowledged.
    pub(crate) const fn highest(&self) -> Option<CmdSeq> {
        self.highest_command
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Passthrough,
    AwaitingScreen,
    ScreenSent,
}

pub(crate) struct Attachment {
    pub(crate) id: AttachmentId,
    pub(crate) stream: ClientStream,
    pub(crate) sink: AttachmentSink,
    pub(crate) framing: Framing,
    /// What this client has confirmed, and what it is still missing.
    pub(crate) ledger: ScreenLedger,
    pub(crate) link: LinkTiming,
    /// This client's own terminal. The session's grid is the smallest of them.
    pub(crate) size: GridSize,
    mode: OutputMode,
    pub(crate) generation: Generation,
    pub(crate) version: ScreenVersion,
    /// When the screen the ledger holds was handed to the sink. At most one is
    /// outstanding: only the last screen pushed can ever be confirmed.
    screen_sent_at: Instant,
    last_repaint: Instant,
    pub(crate) repaint_pending: bool,
    /// The next output byte this client says it wants, from its last `Pong`.
    /// Read only on a datagram, where nothing else notices a client falling
    /// behind.
    pub(crate) consumed: ByteOff,
    /// Where this client's next screen starts carrying deferred sequences from.
    pub(crate) deferred_from: DeferMark,
    /// Where the screen the ledger holds carried up to. Retired on the
    /// acknowledgement, not the encode: nothing retransmits a screen.
    deferred_sent: DeferMark,
    /// Repaints that would not encode since the last one that did: a row of
    /// dense combining marks fails identically forever, which is a livelock.
    encode_failures: u32,
    /// The last screen handed to the sink was larger than one client should hold.
    pub(crate) pressure: sink::ScreenPressure,
    /// Frame buffers the transport has finished with, so the allocator does
    /// not see this client's whole byte stream twice.
    pub(crate) spare: Vec<Vec<u8>>,
    pub(crate) packing: Packing,
    /// What this attachment's ceilings cost the daemon, given back on drop.
    _charge: AttachmentSlot,
}

impl Attachment {
    pub(crate) fn new(
        id: AttachmentId,
        stream: ClientStream,
        sink: AttachmentSink,
        framing: Framing,
        size: GridSize,
        generation: Generation,
        charge: AttachmentSlot,
    ) -> Self {
        let now = Instant::now();
        let packing = framing.packing();
        Self {
            id,
            stream,
            sink,
            framing,
            ledger: ScreenLedger::new(),
            link: LinkTiming::new(),
            size,
            mode: OutputMode::Passthrough,
            generation,
            version: ScreenVersion::initial(),
            screen_sent_at: now,
            last_repaint: now,
            repaint_pending: false,
            consumed: ByteOff::zero(),
            deferred_from: DeferMark(0),
            deferred_sent: DeferMark(0),
            encode_failures: 0,
            pressure: sink::ScreenPressure::Clear,
            spare: Vec::new(),
            packing,
            _charge: charge,
        }
    }

    /// Whether the byte stream may be handed to this client at all: the grid
    /// is the smallest attached terminal, and a larger one autowraps it early.
    pub(crate) fn fits(&self, grid: GridSize) -> bool {
        self.size == grid
    }

    /// Move this client's receive window forward. Monotone: both messages
    /// carrying this number are unsequenced, so either can overtake the other.
    pub(crate) fn consume(&mut self, off: ByteOff) {
        if off.get() > self.consumed.get() {
            self.consumed = off;
        }
    }

    /// Move this client onto a new byte-stream epoch: the generation, the
    /// ledger's base and whatever is in flight move together or not at all.
    pub(crate) fn regrid(&mut self, generation: Generation, rows: u16) {
        self.generation = generation;
        self.ledger.invalidate(rows);
        self.ledger.release_in_flight();
        if self.mode == OutputMode::ScreenSent {
            self.mode = OutputMode::AwaitingScreen;
        }
    }

    /// The same, numbering this client's screens again from one.
    pub(crate) fn restart(&mut self, generation: Generation, rows: u16) {
        self.regrid(generation, rows);
        self.version = ScreenVersion::initial();
    }

    /// Whether this client is served whole screens rather than the byte stream.
    pub(crate) const fn is_syncing(&self) -> bool {
        !matches!(self.mode, OutputMode::Passthrough)
    }

    /// A replay caught this client up, so it is back on the byte stream.
    pub(crate) const fn resumed(&mut self) {
        self.mode = OutputMode::Passthrough;
    }

    /// Take this client's stamp for the screen about to be composed. One
    /// transition: version, armed flag and interval clock are one event.
    pub(crate) fn painting(
        &mut self,
        painted: Painted,
        now: Instant,
    ) -> (Generation, ScreenVersion) {
        if matches!(painted, Painted::Due) {
            self.version = self.version.next();
        }
        self.repaint_pending = false;
        self.last_repaint = now;
        (self.generation, self.version)
    }

    /// The deferred sequences this client has not been given, cut to what one
    /// piece of its screen carries.
    pub(crate) fn owed_deferred(&self, log: &DeferredOsc) -> Vec<String> {
        log.carry(self.deferred_from, self.framing.deferred_budget())
    }

    /// Note the screen that has just reached the sink, and what it carries.
    /// [`Self::confirm`] is what retires the deferred log; this only records.
    pub(crate) const fn sent(&mut self, mark: DeferMark, now: Instant) {
        self.deferred_sent = mark;
        self.screen_sent_at = now;
        if !matches!(self.mode, OutputMode::Passthrough) {
            self.mode = OutputMode::ScreenSent;
        }
    }

    /// Take this client's acknowledgement of the screen the ledger holds. The
    /// deferred log is retired here and nowhere else: a screen the client
    /// never assembled carried nothing, and nothing retransmits it.
    pub(crate) fn confirm(&mut self, generation: Generation, version: ScreenVersion) {
        if self.ledger.confirm(generation, version) {
            self.deferred_from = self.deferred_sent;
        }
    }

    /// What "this client has caught up" means on its own transport.
    pub(crate) fn catch_up(&self, offset: ByteOff) -> gate::CatchUp {
        let drained = self.sink.is_drained();
        match self.framing {
            Framing::Stream => gate::CatchUp::Stream { drained },
            Framing::Datagram { .. } => gate::CatchUp::Datagram {
                drained,
                outstanding: offset.get().saturating_sub(self.consumed.get()),
            },
        }
    }

    /// Leave the sync episode, or keep a repaint armed so the decision is
    /// retaken next interval. A client pinned to screens by its own size arms
    /// nothing, or it repaints for as long as the sizes disagree.
    pub(crate) fn settle(&mut self, caught_up: bool, grid: GridSize) {
        if caught_up {
            self.mode = if self.fits(grid) {
                OutputMode::Passthrough
            } else {
                OutputMode::ScreenSent
            };
        } else {
            self.repaint_pending = true;
        }
    }

    /// Use the silence before a new output run without letting that run erase
    /// the evidence. Passthrough is safe only after a screen was ordered first.
    pub(crate) fn settle_before_output(
        &mut self,
        offset: ByteOff,
        now: Instant,
        last_output: Option<Instant>,
        grid: GridSize,
    ) {
        if self.mode != OutputMode::ScreenSent {
            return;
        }
        let caught_up = gate::may_return_to_passthrough(
            self.catch_up(offset),
            now,
            last_output,
            self.link.repaint_interval(),
        );
        self.settle(caught_up, grid);
    }

    /// How much longer the screen awaiting acknowledgement holds the next back.
    fn ack_hold(&self) -> Duration {
        if self.ledger.in_flight() {
            self.link
                .ack_timeout()
                .saturating_sub(self.screen_sent_at.elapsed())
        } else {
            Duration::ZERO
        }
    }

    /// How much longer a client still holding an oversized screen keeps the
    /// next one back. Nothing clocks this, so the answer is a back-off.
    fn screen_hold(&self) -> Duration {
        if self.pressure == sink::ScreenPressure::Over && !self.sink.is_drained() {
            self.link.repaint_interval()
        } else {
            Duration::ZERO
        }
    }

    /// How much longer an armed repaint is held back, zero when one may go now.
    /// Every gate in one place: a wakeup that models only some of them is a
    /// `recv_timeout` of zero, which is a pinned core.
    pub(crate) fn repaint_hold(&self) -> Duration {
        self.link
            .repaint_interval()
            .saturating_sub(self.last_repaint.elapsed())
            .max(self.ack_hold())
            .max(self.screen_hold())
    }

    /// Whether an armed repaint can go out now. Asking before bumping a screen
    /// version is what keeps a held repaint from burning one per wakeup.
    fn repaint_due(&self) -> bool {
        self.repaint_pending && self.repaint_hold().is_zero()
    }

    /// Enter whole-screen mode, marking where the next screen starts carrying
    /// deferred sequences from, or the client is sent them all again.
    pub(crate) fn begin_sync(&mut self, mark: DeferMark) {
        if self.mode == OutputMode::Passthrough {
            // Never past a screen this client has not confirmed: what that
            // screen carried is still owed.
            if !self.ledger.in_flight() {
                self.deferred_from = mark;
            }
            self.mode = OutputMode::AwaitingScreen;
        }
        self.repaint_pending = true;
    }

    /// How long this client may be left alone before something is owed.
    pub(crate) fn deadline(&self) -> Duration {
        next_deadline(
            self.link
                .ping_interval()
                .saturating_sub(self.link.last_probe.elapsed()),
            self.repaint_pending.then(|| self.repaint_hold()),
        )
    }

    /// Hand one run of PTY output to this client, in its own encoding: the
    /// echo acknowledgement rides in the frame it describes and is per client.
    pub(crate) fn push_output(
        &mut self,
        mut offset: ByteOff,
        bytes: &[u8],
        cue: InputCue,
        now: Instant,
        mark: DeferMark,
    ) -> Result<(), SinkError> {
        // Further behind than a stream's window would have let it get. Treated
        // exactly like a full queue, because it is that fact by another route.
        if matches!(self.framing, Framing::Datagram { .. })
            && offset.get().saturating_sub(self.consumed.get()) > sink::STREAM_LIMIT as u64
        {
            self.begin_sync(mark);
            return Ok(());
        }
        let echo_ack = self.stream.echo_ack(now);
        // One read of the path, not one per chunk: a PMTU that moved mid-read
        // would cut two chunks of it to two bounds for no benefit.
        let chunk_budget = self.framing.output_chunk();
        let mut start = 0;
        // One reclaim per read: the transport retires a whole batch at a time.
        self.sink.reclaim(&mut self.spare);
        while start < bytes.len() {
            let end = (start + chunk_budget).min(bytes.len());
            // Only the last chunk leaves the emulator where the cue says it
            // is; an earlier one would describe a screen the client lacks.
            let chunk = if end == bytes.len() {
                cue
            } else {
                InputCue::Opaque
            };
            let mut frame = self.spare.pop().unwrap_or_default();
            encode_output_into(&mut frame, offset, chunk, echo_ack, &bytes[start..end])
                .map_err(|_| SinkError::Unusable)?;
            match self.sink.send_output(frame) {
                Ok(()) => {}
                Err(SinkError::Full) => {
                    // This client is behind. Switch it - and only it - to
                    // whole screens, which coalesce in place instead of
                    // queuing every intermediate state. What is already queued
                    // is dropped with it: the screen this arms describes the
                    // terminal after every one of those frames.
                    self.sink.discard_stream();
                    self.begin_sync(mark);
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            offset = offset.checked_add(end - start).ok_or(SinkError::Unusable)?;
            start = end;
        }
        Ok(())
    }

    /// Send this client the current screen, as a delta when it confirmed a
    /// base; a delta carries every row the confirmed screen lacks, so nothing
    /// here reconciles. The header is the caller's, built once per repaint.
    pub(crate) fn push_screen(
        &mut self,
        header: &ScreenHeader,
        frame: &RepaintFrame,
    ) -> Result<Painting, SinkError> {
        // The ledger decides and records in one call, so what a screen claims
        // to carry and what the encoder emits cannot drift apart.
        let fits = self.fits(frame.size);
        // Read here rather than held on the attachment: a path that just
        // raised its MTU should cut this screen to the larger bound.
        let budget = self.framing.screen_budget();
        let encoded = {
            // Destructured so the ledger's borrow and the frame pool's are
            // disjoint from the packing state's.
            let Self {
                ledger,
                packing,
                spare,
                ..
            } = self;
            let plan = ledger.plan(frame, header);
            screen_pieces(budget, packing, header, plan, frame, fits, spare)
        };
        let Ok(encoded) = encoded else {
            // Not a `Reject`, which is terminal and would end a session whose
            // shell is still running the user's work. The ledger still owes
            // these rows, but re-arming forever is a livelock: after
            // [`ENCODE_ATTEMPTS`] only new PTY output arms a repaint.
            self.ledger.release_in_flight();
            self.encode_failures = self.encode_failures.saturating_add(1);
            if self.encode_failures < ENCODE_ATTEMPTS {
                self.repaint_pending = true;
            } else if self.encode_failures == ENCODE_ATTEMPTS {
                log!(
                    "a {}x{} screen has not encoded in {ENCODE_ATTEMPTS} attempts; \
                     this client is no longer being repainted on a timer",
                    frame.size.cols,
                    frame.size.rows
                );
            }
            return Ok(Painting::Withheld);
        };
        self.encode_failures = 0;
        match self.sink.send_screen(encoded) {
            Ok(pressure) => {
                if pressure == sink::ScreenPressure::Over
                    && self.pressure == sink::ScreenPressure::Clear
                {
                    log!(
                        "a {}x{} screen is larger than one attachment should hold; \
                         pacing this client against its transport",
                        frame.size.cols,
                        frame.size.rows
                    );
                }
                self.pressure = pressure;
            }
            Err(error) => {
                // Nothing went out, so the ledger must not hold the next
                // screen back for an acknowledgement that can never come.
                self.ledger.release_in_flight();
                return Err(error);
            }
        }
        Ok(Painting::Sent)
    }
}

/// Whether a repaint actually reached the sink.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Painting {
    Sent,
    /// It would not encode. Nothing left the session, so everything the screen
    /// would have carried is still owed.
    Withheld,
}

/// How a screen is cut for one client's transport. A datagram packs every
/// frame it seals, so pieces are planned against the gain deflate is expected
/// to give and then packed to find out: the estimate is never a correctness
/// argument.
pub(crate) enum Packing {
    Exact,
    Packed(Packed),
}

/// One whole point of compression gain. Fixed point rather than a float: a
/// budget that depends on rounding mode fragments on some machines only.
const RATIO_ONE: usize = 256;

/// What an attachment's first screen is cut against: half the 4.74x
/// `braid_proto::wire` measures on this traffic, because cutting too large
/// costs a re-encode and too small costs only the datagrams it did not save.
const RATIO_START: usize = 2 * RATIO_ONE;

/// The most gain an estimate may claim: above the measured 4.74x with room
/// for a screen of blanks, far below deflate's thousandfold on a blank one.
const RATIO_CEILING: usize = 6 * RATIO_ONE;

/// The optimistic cut's state: what the last screen packed to, and the pieces
/// that packing produced.
pub(crate) struct Packed {
    /// The worst piece of the last screen's gain, in [`RATIO_ONE`]ths.
    ratio: usize,
    /// The accepted cut as the datagram carries it: each piece length-prefixed,
    /// with the codec's tag where the stream framing's payload would start.
    ///
    /// Kept rather than discarded, because packing *is* the measurement: the
    /// pieces have to go through the codec to find out whether they fit the
    /// path, so packing the accepted cut again to send it would deflate every
    /// screen on this path twice.
    carried: Vec<Vec<u8>>,
}

impl Packed {
    pub(crate) fn new() -> Self {
        Self {
            ratio: RATIO_START,
            carried: Vec::new(),
        }
    }

    /// Pack every piece to find what the path really carries. The worst
    /// piece's gain rather than the aggregate: a screen is only as cuttable as
    /// its least compressible piece.
    fn measure(
        &mut self,
        pieces: &[Vec<u8>],
        limit: usize,
        spare: &mut Vec<Vec<u8>>,
    ) -> (usize, bool) {
        let mut worst = RATIO_CEILING;
        let mut fits = true;
        // Buffers survive the re-cuts within one screen; between screens they
        // come back through the sink's spare pool with the frames they became.
        self.carried
            .resize_with(pieces.len(), || spare.pop().unwrap_or_default());
        for (piece, carried) in pieces.iter().zip(&mut self.carried) {
            // The length prefix does not travel on a datagram; the codec tag
            // takes its place, and `pack_from` writes that tag itself.
            let payload = piece.get(FRAME_LENGTH_PREFIX..).unwrap_or_default();
            // Only grow: `pack_from` overwrites every byte from here, and
            // truncating first would make `room_for` zero the whole payload.
            if carried.len() < FRAME_LENGTH_PREFIX {
                carried.resize(FRAME_LENGTH_PREFIX, 0);
            }
            pack_from(payload, carried, FRAME_LENGTH_PREFIX);
            // The wire's own framing, so a piece this daemon cut can never carry
            // a length prefix `braid_proto` would not have written.
            if braid_proto::seal_frame(carried).is_err() {
                return (RATIO_ONE, false);
            }
            let packed = carried.len() - FRAME_LENGTH_PREFIX;
            fits &= packed <= limit;
            worst = worst.min(payload.len().saturating_mul(RATIO_ONE) / packed.max(1));
        }
        (worst.clamp(RATIO_ONE, RATIO_CEILING), fits)
    }

    /// The pieces the last measurement packed, which is the cut that was
    /// accepted. Taken, so a screen's frames leave with it.
    fn take_carried(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.carried)
    }

    /// Fold what a screen packed to into the estimate: down at once and up by
    /// a quarter of the error, because too high costs a whole re-cut.
    pub(crate) fn observed(&mut self, measured: usize) {
        self.ratio = if measured < self.ratio {
            measured
        } else {
            self.ratio + (measured - self.ratio) / 4
        };
    }
}

/// Repaints that may fail to encode before the clock stops driving them.
const ENCODE_ATTEMPTS: u32 = 2;

/// Encode one screen as the frames its transport will carry; the budget is the
/// whole difference between the two framings. The row batch is the unit on a
/// datagram, where the piece the path carries is the *packed* one: the cut is
/// planned optimistically, verified by packing, halved and re-cut if it
/// overruns - and the packing that verified it is the packing that is sent.
fn screen_pieces(
    budget: usize,
    packing: &mut Packing,
    header: &ScreenHeader,
    plan: &screen::Plan,
    frame: &RepaintFrame,
    fits: bool,
    spare: &mut Vec<Vec<u8>>,
) -> Result<Cut, EncodeError> {
    // A delta's scroll only moves the rows it names when the grid is the whole
    // terminal; a taller client refuses it and asks for a screen anyway.
    let whole = plan.full || (plan.scroll.is_some() && !fits);
    let Packing::Packed(packed) = packing else {
        return Ok(Cut {
            pieces: attempt(header, plan, frame, whole, budget)?,
            coding: Coding::Raw,
        });
    };
    // What the datagram itself carries: the length prefix comes off and the
    // codec tag goes on.
    let limit = dgram::payload_limit(budget);
    let mut planned = limit.saturating_mul(packed.ratio) / RATIO_ONE;
    loop {
        planned = planned.max(budget);
        let pieces = attempt(header, plan, frame, whole, planned)?;
        if pieces.is_empty() {
            return Ok(Cut {
                pieces,
                coding: Coding::Raw,
            });
        }
        let (measured, carried) = packed.measure(&pieces, limit, spare);
        packed.observed(measured);
        // At the raw bound nothing smaller is available or needed: `pack`
        // never returns more than its input plus a tag.
        if carried || planned <= budget {
            // The raw cut has served its purpose; its buffers go back to the
            // pool the packed ones were drawn from.
            recycle(pieces, spare);
            return Ok(Cut {
                pieces: packed.take_carried(),
                coding: Coding::Packed,
            });
        }
        recycle(pieces, spare);
        planned /= 2;
    }
}

/// Return frame buffers to the attachment's pool, under the bound the sink
/// keeps its own by.
fn recycle(pieces: Vec<Vec<u8>>, spare: &mut Vec<Vec<u8>>) {
    for piece in pieces {
        sink::recycle(spare, piece);
    }
}

/// One cut at a given piece budget, dropping what cannot be cut if the exact
/// attempt will not fit.
pub(crate) fn attempt(
    header: &ScreenHeader,
    plan: &screen::Plan,
    frame: &RepaintFrame,
    whole: bool,
    budget: usize,
) -> Result<Vec<Vec<u8>>, EncodeError> {
    match cut(header, plan, frame, whole, budget, Fidelity::Exact) {
        // A span too wide for any piece fails the same way on every repaint,
        // and a row missing its end beats a screen that never arrives.
        Err(EncodeError::Oversize) => cut(header, plan, frame, whole, budget, Fidelity::Lossy),
        cut => cut,
    }
}

/// Whether a span too wide for any piece may be dropped.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fidelity {
    /// Every span as the emulator built it.
    Exact,
    /// Spans that will not fit dropped, which costs the end of a line.
    Lossy,
}

pub(crate) fn cut(
    header: &ScreenHeader,
    plan: &screen::Plan,
    frame: &RepaintFrame,
    whole: bool,
    budget: usize,
    fidelity: Fidelity,
) -> Result<Vec<Vec<u8>>, EncodeError> {
    if whole {
        let count = u16::try_from(frame.rows.len()).map_err(|_| EncodeError::Oversize)?;
        let every = (0..count).map(|row| {
            degraded(
                RowUpdate::whole(row, &frame.rows[usize::from(row)]),
                fidelity,
                budget,
            )
        });
        return encode_screen_parts(header, None, None, every, budget);
    }
    let named = plan.rows.iter().map(|named| {
        let row = &frame.rows[usize::from(named.row)];
        degraded(named.update(row), fidelity, budget)
    });
    match encode_screen_parts(header, Some(plan.base), plan.scroll, named, budget) {
        // A scroll survives only in a single piece and carries only the rows
        // it reveals, so one that did not fit is refused rather than dropped:
        // the whole screen is the applicable answer.
        Err(EncodeError::Oversize) if plan.scroll.is_some() => {
            cut(header, plan, frame, true, budget, fidelity)
        }
        cut => cut,
    }
}

fn degraded(one: RowUpdate<'_>, fidelity: Fidelity, budget: usize) -> RowUpdate<'_> {
    match fidelity {
        Fidelity::Exact => one,
        Fidelity::Lossy => shortened(one, budget),
    }
}

/// The row update with any span too wide to be cut across pieces removed. A
/// span boundary is a style-run boundary - the only offset at which both a
/// column and a byte position are known - so a run wider than a whole piece is
/// the one thing row chunking can never get smaller. Zalgo text and heavily
/// decomposed Devanagari both build one.
fn shortened(update: RowUpdate<'_>, budget: usize) -> RowUpdate<'_> {
    let (start, end) = update.runs;
    let mut kept = end;
    for (offset, run) in update.frame.runs[start.min(end)..end].iter().enumerate() {
        if run.bytes as usize > budget {
            kept = start + offset;
            break;
        }
    }
    // Everything past the last run is one implicit span under the same bound,
    // and it travels only with a range reaching the end of the runs.
    if kept == end
        && end == update.frame.runs.len()
        && update.frame.text.len() - update.frame.styled_bytes() > budget
    {
        kept = end.saturating_sub(1);
    }
    if kept == end {
        return update;
    }
    RowUpdate {
        runs: (start, kept),
        // The columns past it are whatever the client last painted there.
        clear_tail: true,
        ..update
    }
}

/// Which attachments a repaint pass is for. [`Self::Due`] is the paced steady
/// state and takes the next version; [`Self::One`] follows a caller that has
/// just started a generation, whose first screen is version one.
#[derive(Clone, Copy)]
pub(crate) enum Painted {
    Due,
    One(AttachmentId),
}

impl Painted {
    pub(crate) fn wants(self, attachment: &Attachment) -> bool {
        match self {
            Self::Due => attachment.repaint_due(),
            Self::One(id) => {
                attachment.id == id && attachment.repaint_pending && attachment.ack_hold().is_zero()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defer::*;
    use crate::screen::ScreenLedger;
    use crate::sink::*;
    use crate::testing::*;
    use crate::*;
    use braid_proto::{
        ByteOff, CmdSeq, Generation, GridSize, InputCue, RowUpdate, ScreenHeader, ScreenPart,
        ScreenVersion, ServerMessage, Version,
    };
    use braid_vt::RepaintFrame;
    use std::time::{Duration, Instant};

    /// The header a repaint pass builds, for a test driving one attachment
    /// without one.
    fn header_of(
        generation: Generation,
        version: ScreenVersion,
        frame: &RepaintFrame,
    ) -> ScreenHeader {
        ScreenHeader {
            generation,
            version,
            next_off: ByteOff::zero(),
            size: frame.size,
            cursor: frame.cursor,
            cursor_visible: frame.cursor_visible,
            cursor_shape: frame.cursor_shape,
            cursor_blinking: frame.cursor_blinking,
            modes: frame.modes,
            sticky: frame.sticky.clone(),
        }
    }

    /// Push one screen the way `SessionActor::repaint` does.
    fn paint(attachment: &mut Attachment, frame: &RepaintFrame) -> Result<Painting, SinkError> {
        paint_carrying(attachment, frame, Vec::new())
    }

    /// The same, for a screen owed deferred sequences.
    fn paint_carrying(
        attachment: &mut Attachment,
        frame: &RepaintFrame,
        deferred: Vec<String>,
    ) -> Result<Painting, SinkError> {
        let mut header = header_of(attachment.generation, attachment.version, frame);
        header.sticky.deferred = deferred;
        attachment.push_screen(&header, frame)
    }

    /// A repaint of these rows, every one of them dirty.
    fn frame_of(grid: GridSize, rows: Vec<braid_proto::RowFrame>) -> RepaintFrame {
        RepaintFrame {
            size: grid,
            rows,
            cursor: Some((0, 0)),
            cursor_visible: true,
            cursor_shape: braid_proto::CursorShape::Unset,
            cursor_blinking: false,
            modes: braid_proto::ModeSet::default(),
            sticky: braid_proto::StickyState::default(),
            dirty: braid_vt::RowMask::filled(grid.rows),
        }
    }

    /// A screen of `rows` distinguishable lines, numbered from `first`.
    fn lines_frame(grid: GridSize, first: usize, text: impl Fn(usize) -> String) -> RepaintFrame {
        frame_of(
            grid,
            (first..first + usize::from(grid.rows))
                .map(|line| braid_proto::RowFrame {
                    text: text(line),
                    runs: Vec::new(),
                    cells: grid.cols,
                })
                .collect(),
        )
    }

    fn test_frame(grid: GridSize, first: usize) -> RepaintFrame {
        lines_frame(grid, first, |line| format!("line {line}"))
    }

    /// The same with rows wide enough that a grid of them costs more than one
    /// datagram, which is the case every cut exists for.
    fn wide_frame(grid: GridSize, first: usize) -> RepaintFrame {
        lines_frame(grid, first, |line| {
            format!("{line:->width$}", width = usize::from(grid.cols))
        })
    }

    /// Wait until this attachment's transport has taken `count` frames.
    fn written_frames(output: &TestOutput, count: usize) -> bool {
        settles(Duration::from_secs(2), || output.frames().len() >= count)
    }

    /// A frame of the traffic the repaint path actually carries: source lines
    /// under a handful of style runs apiece, which is what `braid_proto::wire`
    /// measured its compression ratio against.
    fn highlighted_frame(grid: GridSize) -> RepaintFrame {
        const KEYWORDS: [&str; 6] = [
            "pub fn ", "let mut ", "return ", "match ", "impl ", "const ",
        ];
        let rows = (0..usize::from(grid.rows))
            .map(|line| {
                let mut text = format!(
                    "{:indent$}{}render_{line}(frame: &RepaintFrame, out: &mut Vec<u8>) -> usize \
                     {{ // piece {line} of one repaint",
                    "",
                    KEYWORDS[line % KEYWORDS.len()],
                    indent = line % 8,
                );
                text.truncate(usize::from(grid.cols));
                let chunk = text.len().div_ceil(5).max(1);
                let runs = text
                    .as_bytes()
                    .chunks(chunk)
                    .enumerate()
                    .map(|(index, part)| braid_proto::StyleRun {
                        cells: u16::try_from(part.len()).expect("a run width"),
                        bytes: u32::try_from(part.len()).expect("a run length"),
                        style: braid_proto::CellStyle {
                            fg: braid_proto::StyleColor::Palette(
                                u8::try_from(index).expect("a palette index") + 1,
                            ),
                            ..braid_proto::CellStyle::default()
                        },
                    })
                    .collect();
                braid_proto::RowFrame {
                    text,
                    runs,
                    cells: grid.cols,
                }
            })
            .collect();
        frame_of(grid, rows)
    }

    /// One whole screen cut for a datagram path at the floor budget, under a
    /// given packing.
    fn datagram_pieces(packing: &mut Packing, frame: &RepaintFrame) -> Cut {
        let mut ledger = ScreenLedger::new();
        ledger.invalidate(frame.size.rows);
        ledger.note_damage(&frame.dirty);
        let header = header_of(Generation::initial(), ScreenVersion::initial(), frame);
        let plan = ledger.plan(frame, &header);
        let mut spare = Vec::new();
        screen_pieces(
            DATAGRAM_BUDGET,
            packing,
            &header,
            plan,
            frame,
            true,
            &mut spare,
        )
        .expect("the screen encodes")
    }

    /// One attachment with no session behind it, which is all the screen and
    /// output paths need.
    fn framed_attachment(framing: Framing, size: GridSize) -> (Attachment, TestOutput) {
        let output = TestOutput::new();
        let attachment = Attachment::new(
            next_attachment(),
            ClientStream::new(client(1)),
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
            framing,
            size,
            Generation::initial(),
            test_charge(),
        );
        (attachment, output)
    }

    /// One datagram attachment on the standard grid, holding no screen yet.
    fn datagram_attachment() -> (Attachment, TestOutput) {
        let (mut attachment, output) = framed_attachment(datagram(DATAGRAM_BUDGET), GRID);
        attachment.ledger.invalidate(GRID.rows);
        (attachment, output)
    }

    /// Push `frame` the way a repaint pass does: damage noted, then the screen.
    fn repaint(attachment: &mut Attachment, frame: &RepaintFrame) -> Result<Painting, SinkError> {
        attachment.ledger.note_damage(&frame.dirty);
        paint(attachment, frame)
    }

    /// Every screen piece this attachment was sent, in order.
    fn screen_parts(output: &TestOutput) -> Vec<ScreenPart> {
        output
            .frames()
            .into_iter()
            .filter_map(|message| match message {
                ServerMessage::Screen { part } => Some(part),
                _ => None,
            })
            .collect()
    }

    /// The rows a run of pieces carries between them, in ascending order.
    fn named_rows(pieces: &[ScreenPart]) -> Vec<u16> {
        let mut rows: Vec<u16> = pieces
            .iter()
            .flat_map(|piece| match piece {
                ScreenPart::Head { rows, .. } | ScreenPart::Tail { rows, .. } => rows,
            })
            .map(|row| row.row)
            .collect();
        rows.sort_unstable();
        rows
    }

    /// The packed size of every piece this attachment was sent, each of which
    /// has to fit the datagram it was planned for.
    fn fitting_sizes(output: &TestOutput) -> Vec<usize> {
        let sizes = output.packed_sizes();
        assert!(
            sizes
                .iter()
                .all(|&size| size <= dgram::payload_limit(DATAGRAM_BUDGET)),
            "a piece overran the datagram it was cut for once packed: {sizes:?}"
        );
        sizes
    }

    /// A row carrying one style run wider than any piece: chunks are cut at
    /// run boundaries, so this is the last screen the encoder can still refuse.
    fn unchunkable_frame(grid: GridSize) -> RepaintFrame {
        let bytes = DATAGRAM_BUDGET * 4;
        let mut frame = wide_frame(grid, 0);
        frame.rows[0] = braid_proto::RowFrame {
            text: "x".repeat(bytes),
            runs: vec![braid_proto::StyleRun {
                cells: grid.cols,
                bytes: u32::try_from(bytes).expect("a run length"),
                style: braid_proto::CellStyle::default(),
            }],
            cells: grid.cols,
        };
        frame
    }

    /// The wakeup and the send are one predicate asked at two moments. Model
    /// them separately and a wakeup with nothing to do at the end of it is a
    /// pinned core per affected session.
    #[test]
    fn the_repaint_deadline_is_zero_exactly_when_a_repaint_can_be_served() {
        let stalled = StalledOutput::new();
        let mut attachment = Attachment::new(
            next_attachment(),
            ClientStream::new(client(1)),
            AttachmentSink::new(stalled.clone(), Version::LOCAL).expect("attachment"),
            Framing::Stream,
            GRID,
            Generation::initial(),
            test_charge(),
        );

        // Nothing armed: the only wakeup owed is the probe's.
        assert!(!attachment.repaint_due());
        assert!(!attachment.deadline().is_zero());

        // Armed, and every clock has run out.
        attachment.repaint_pending = true;
        attachment.last_repaint = Instant::now()
            .checked_sub(REPAINT_CEILING * 2)
            .expect("a monotonic clock past its own ceiling");
        assert!(attachment.repaint_due(), "nothing is holding it back");
        assert!(attachment.deadline().is_zero());

        // The transport has not taken the last screen, and that screen was
        // larger than one a stalled client should be made to hold.
        attachment
            .sink
            .send(&ServerMessage::Ping {
                token: 1,
                echo_ack: None,
                interval_ms: 250,
            })
            .expect("a live sink");
        attachment.pressure = sink::ScreenPressure::Over;
        assert!(
            !attachment.sink.is_drained(),
            "the transport is stalled, which is what this is about"
        );
        assert!(
            !attachment.repaint_due(),
            "an oversized screen is still outstanding"
        );
        assert!(
            !attachment.deadline().is_zero(),
            "a wakeup with nothing to do at the end of it is a pinned core"
        );

        // And the two clear together, because there is one predicate.
        attachment.pressure = sink::ScreenPressure::Clear;
        assert!(attachment.repaint_due());
        assert!(attachment.deadline().is_zero());

        stalled.release();
        attachment.sink.close();
    }

    /// The echo ack is what lets a client tell "not answered yet" from "my
    /// prediction was wrong", so it must not advance before the application
    /// has had the command - including when a paste storm overruns the ring.
    #[test]
    fn the_echo_ack_publishes_only_what_the_application_has_had() {
        let mut echo = EchoAck::new();
        let start = Instant::now();
        echo.recorded(CmdSeq::first(), start);
        assert_eq!(echo.published(start), None);
        assert_eq!(echo.published(start + ECHO_TIMEOUT / 2), None);
        assert_eq!(echo.published(start + ECHO_TIMEOUT), Some(CmdSeq::first()));

        // Newer commands do not drag an older one over the line with them.
        let second = CmdSeq::first().next();
        let later = start + ECHO_TIMEOUT;
        echo.recorded(second, later);
        assert_eq!(echo.published(later), Some(CmdSeq::first()));
        assert_eq!(echo.published(later + ECHO_TIMEOUT), Some(second));

        let mut flooded = EchoAck::new();
        let mut number = CmdSeq::first();
        for _ in 0..(ECHO_HISTORY * 4) {
            flooded.recorded(number, start);
            number = number.next();
        }
        assert!(flooded.pending.len() <= ECHO_HISTORY);
        assert_eq!(
            flooded.published(start),
            None,
            "an overrun ring released a prediction that is still speculative"
        );
    }

    /// A replay after a transport swap is acknowledged without being applied
    /// again, and a gap is reported rather than skipped: a gate that skipped
    /// would reject every later sequence for the life of the session.
    #[test]
    fn the_command_gate_answers_replays_and_gaps_without_wedging() {
        let mut gate = CommandGate::new();
        let first = CmdSeq::first();
        let second = first.next();
        assert!(gate.admit(first) == Admission::Fresh);
        assert!(gate.admit(second) == Admission::Fresh);
        assert!(gate.admit(first) == Admission::Duplicate);
        assert!(gate.admit(second) == Admission::Duplicate);
        // The gate is not rewound by the replay.
        assert!(gate.admit(second.next()) == Admission::Fresh);

        let mut gapped = CommandGate::new();
        assert!(gapped.admit(CmdSeq::first()) == Admission::Fresh);
        assert!(gapped.admit(seq(4)) == Admission::Gap);
        // The lost command still owes its slot.
        assert!(gapped.admit(CmdSeq::first().next()) == Admission::Fresh);
    }

    /// A client taller than the grid refuses a delta that scrolls, because the
    /// shortcut walks the cursor down instead, so it is sent the screen it
    /// would have asked for rather than the round trip that asks.
    #[test]
    fn a_scrolling_delta_is_never_sent_to_a_client_larger_than_the_grid() {
        let grid = GridSize::new(80, 8).expect("valid test size");
        let (mut attachment, output) = framed_attachment(
            Framing::Stream,
            GridSize::new(80, 12).expect("valid test size"),
        );
        attachment.ledger.invalidate(grid.rows);

        let first = test_frame(grid, 0);
        attachment.ledger.note_damage(&first.dirty);
        paint(&mut attachment, &first).expect("the first screen goes out whole");
        assert!(
            attachment
                .ledger
                .confirm(attachment.generation, attachment.version),
            "the client confirms the base a delta would be planned against"
        );
        // A screen supersedes the one still queued, so the second is pushed
        // only once the first has actually gone out.
        assert!(written_frames(&output, 1), "the first screen goes out");

        // The whole viewport moved up one line, which is the one shape
        // `ScreenLedger` answers with a scroll.
        attachment.version = attachment.version.next();
        let scrolled = test_frame(grid, 1);
        attachment.ledger.note_damage(&scrolled.dirty);
        paint(&mut attachment, &scrolled).expect("the second screen goes out");

        assert!(written_frames(&output, 2), "both screens reach the client");
        let frames = output.frames();
        assert_eq!(frames.len(), 2, "both screens reach the client");
        assert!(
            matches!(
                frames[1],
                ServerMessage::Screen {
                    part: ScreenPart::Head { base: None, .. }
                }
            ),
            "a client taller than the grid was sent {:?}",
            frames[1]
        );
        attachment.sink.close();
    }

    /// `braid_proto::wire` exists for piece count under loss, and halving the
    /// count squares the odds. Cutting against the raw MTU instead makes each
    /// of the seventeen datagrams smaller rather than making there be fewer.
    #[test]
    fn a_repaint_is_cut_against_what_the_path_carries_once_packed() {
        let grid = GridSize::new(200, 50).expect("valid test size");
        let screen = highlighted_frame(grid);

        let raw = datagram_pieces(&mut Packing::Exact, &screen).pieces.len();
        let mut packing = datagram(DATAGRAM_BUDGET).packing();
        let cut = datagram_pieces(&mut packing, &screen);

        // Correctness is the verification and never the estimate. The pieces
        // are the packing that verified them, so this measures what the
        // datagram carries rather than a second packing of the same bytes.
        assert!(
            cut.coding == Coding::Packed,
            "a datagram cut arrives through the codec"
        );
        let limit = dgram::payload_limit(DATAGRAM_BUDGET);
        for piece in &cut.pieces {
            let carried = piece.len() - FRAME_LENGTH_PREFIX;
            assert!(
                carried <= limit,
                "a piece packs to {carried} bytes on a path that carries {limit}"
            );
        }
        assert!(
            cut.pieces.len() * 2 <= raw,
            "the compression-aware cut saved nothing: {raw} pieces became {}",
            cut.pieces.len()
        );
    }

    /// Nothing fragments on this path: a frame larger than a datagram is one
    /// the client never receives, so the chunk is cut against the frame's
    /// whole size and not against the bytes inside it.
    #[test]
    fn output_to_a_datagram_client_fits_one_datagram() {
        let (mut attachment, output) = framed_attachment(datagram(DATAGRAM_BUDGET), GRID);
        let bytes = vec![b'x'; 16 * 1024];
        attachment
            .push_output(
                ByteOff::zero(),
                &bytes,
                InputCue::Echoing { room: 40 },
                Instant::now(),
                DeferMark(0),
            )
            .expect("the byte stream goes out");

        let expected = bytes
            .len()
            .div_ceil(datagram(DATAGRAM_BUDGET).output_chunk());
        assert!(written_frames(&output, expected), "every chunk goes out");
        let sizes = output.frame_sizes();
        assert!(
            sizes.iter().all(|&size| size <= DATAGRAM_BUDGET),
            "a frame overran the path it was cut for: {sizes:?}"
        );
        assert_eq!(
            passthrough(&output).len(),
            bytes.len(),
            "the run was cut to fit and then lost some of itself"
        );
        attachment.sink.close();
    }

    /// The row batch is the unit on a datagram: each piece is independently
    /// applicable, so a lost one costs its rows rather than the screen.
    #[test]
    fn a_screen_too_large_for_one_datagram_is_sent_in_pieces() {
        let (mut attachment, output) = datagram_attachment();
        let screen = wide_frame(GRID, 0);
        repaint(&mut attachment, &screen).expect("the screen goes out");

        assert!(written_frames(&output, 2), "one screen, several pieces");
        let sizes = fitting_sizes(&output);
        let pieces = screen_parts(&output);
        assert_eq!(
            pieces.len(),
            sizes.len(),
            "a datagram client was sent something that is not a piece"
        );
        assert!(
            matches!(pieces.first(), Some(ScreenPart::Head { .. })),
            "the first piece carries the header"
        );
        assert_eq!(
            named_rows(&pieces),
            (0..GRID.rows).collect::<Vec<_>>(),
            "the pieces together are the screen"
        );
        attachment.sink.close();
    }

    /// The path MTU moves while the session runs, which is why
    /// [`Framing::Datagram`] carries a handle: a budget read once at attach
    /// would pin every session to the 1200-byte IPv6 floor for its whole life.
    #[test]
    fn a_raised_path_limit_is_used_by_the_next_screen() {
        let limit = dgram::PayloadLimit::fixed(DATAGRAM_BUDGET);
        let (mut attachment, output) = framed_attachment(
            Framing::Datagram {
                budget: limit.clone(),
            },
            GRID,
        );
        let whole_screen = |attachment: &mut Attachment| {
            // Invalidating each time is the only thing that makes two whole
            // screens of the same rows: a confirmed base would make the second
            // one an empty delta.
            attachment.ledger.invalidate(GRID.rows);
            attachment.version = attachment.version.next();
            repaint(attachment, &wide_frame(GRID, 0)).expect("the screen goes out");
        };

        whole_screen(&mut attachment);
        assert!(written_frames(&output, 2), "the floor cuts this in pieces");
        let floored = fitting_sizes(&output);

        limit.publish(braid_dgram::MAX_PAYLOAD);
        whole_screen(&mut attachment);
        assert!(
            written_frames(&output, floored.len() + 1),
            "the second screen never reached the transport"
        );
        // By what the frame carries rather than how big it is: the frames a
        // datagram client is sent are already packed, so their size measures
        // the codec rather than the cut.
        let raised = screen_parts(&output).split_off(floored.len());
        assert_eq!(raised.len(), 1, "the raised path takes the screen whole");
        assert_eq!(
            named_rows(&raised),
            (0..GRID.rows).collect::<Vec<_>>(),
            "the screen was still cut to the budget the attachment started at"
        );
        attachment.sink.close();
    }

    /// A scroll carries only the rows it reveals, so one that does not fit a
    /// single piece cannot simply lose its scroll: the whole screen is the
    /// applicable answer, exactly as it is for a delta naming every row.
    #[test]
    fn a_scroll_too_large_for_one_datagram_is_sent_as_a_whole_screen() {
        let (mut attachment, output) = datagram_attachment();
        let base = wide_frame(GRID, 0);
        repaint(&mut attachment, &base).expect("the base goes out");
        assert!(
            attachment
                .ledger
                .confirm(attachment.generation, attachment.version),
            "the client confirms the base a delta would be planned against"
        );
        // The pieces of one screen are handed to the transport together, so
        // waiting for the second is what makes the count below the base's
        // whole set rather than the part of it the writer had reached.
        assert!(written_frames(&output, 2), "the base goes out in pieces");
        let base_pieces = output.frame_sizes().len();

        // Thirteen rows of eighty columns is more than one datagram holds, so
        // the scroll this shift plans cannot survive the cut.
        attachment.version = attachment.version.next();
        let scrolled = wide_frame(GRID, 13);
        repaint(&mut attachment, &scrolled).expect("the scrolled screen is not dropped");

        assert!(
            written_frames(&output, base_pieces + 2),
            "the retry never went out"
        );
        fitting_sizes(&output);
        let mut pieces = screen_parts(&output);
        let pieces = pieces.split_off(base_pieces);
        assert!(
            matches!(
                pieces.first(),
                Some(ScreenPart::Head {
                    base: None,
                    scroll: None,
                    ..
                })
            ),
            "the retry kept a scroll or a base it cannot honour: {:?}",
            pieces.first()
        );
        assert_eq!(
            named_rows(&pieces),
            (0..GRID.rows).collect::<Vec<_>>(),
            "a screen that dropped its scroll must name every row"
        );
        attachment.sink.close();
    }

    /// A row carrying one style run wider than a whole piece is the one thing
    /// row chunking can never get smaller, and the screen still has to arrive:
    /// it costs the glyphs off the end of that one row.
    #[test]
    fn a_row_no_piece_can_carry_is_shortened_rather_than_costing_the_screen() {
        let (mut attachment, output) = datagram_attachment();
        let refused = unchunkable_frame(GRID);

        repaint(&mut attachment, &refused)
            .expect("a screen that will not encode whole is not a dead attachment");

        assert!(written_frames(&output, 1), "the screen reaches the client");
        assert_eq!(
            named_rows(&screen_parts(&output)),
            (0..GRID.rows).collect::<Vec<_>>(),
            "every row is named, including the one that had to be cut back"
        );
        fitting_sizes(&output);
        assert_eq!(
            attachment.encode_failures, 0,
            "a screen that went out is not a failure to retry"
        );
        assert!(
            !attachment.repaint_pending,
            "nothing is owed: the client has the screen"
        );
        attachment.sink.close();
    }

    /// The lossy cut cannot save a header that alone overruns a piece, and a
    /// persistent failure re-arming itself is a livelock at the repaint
    /// interval for the life of the session.
    #[test]
    fn a_screen_that_cannot_encode_at_all_stops_re_arming_the_repaint_clock() {
        let (mut attachment, output) = datagram_attachment();
        let frame = wide_frame(GRID, 0);
        // Past `Framing::deferred_budget`, which is what the repaint path
        // trims to, and past the budget the compression-aware cut plans its
        // first attempt against: a header this size fits no piece, and the
        // lossy retry cannot shorten a header.
        let entry = "A".repeat(braid_proto::MAX_DEFERRED_BYTES - 128);
        assert!(
            entry.len() > dgram::payload_limit(DATAGRAM_BUDGET) * RATIO_START / RATIO_ONE,
            "a header the first cut would simply carry proves nothing"
        );
        let oversized = || vec![format!("52;c;{entry}")];

        attachment.ledger.note_damage(&frame.dirty);
        paint_carrying(&mut attachment, &frame, oversized())
            .expect("a screen that will not encode is not a dead attachment");
        assert!(output.frames().is_empty());
        assert!(
            attachment.repaint_pending,
            "the first failure is worth retrying"
        );
        assert!(
            !attachment.ledger.in_flight(),
            "the ledger holds a screen back for an acknowledgement that cannot come"
        );

        for _ in 1..ENCODE_ATTEMPTS + 2 {
            attachment.repaint_pending = false;
            paint_carrying(&mut attachment, &frame, oversized())
                .expect("still not a dead attachment");
        }
        assert!(
            !attachment.repaint_pending,
            "a persistent failure re-armed itself forever"
        );

        // Still an attachment: the next screen it can encode goes out on it,
        // and one that does resets the count.
        paint(&mut attachment, &frame).expect("the next screen goes out");
        assert!(written_frames(&output, 1), "the session was lost after all");
        assert_eq!(attachment.encode_failures, 0);
        attachment.sink.close();
    }

    /// `encode_row_chunk`'s bound is an aggregate over a chunk, so a row
    /// carrying one style run wider than a whole piece fails identically on
    /// every repaint forever. A row missing the glyphs off its end beats a
    /// screen that never arrives.
    #[test]
    fn a_span_too_wide_for_any_piece_is_dropped_rather_than_retried_forever() {
        use braid_proto::{CellStyle, RowFrame, StyleRun};
        let run = |cells: u16, bytes: u32| StyleRun {
            cells,
            bytes,
            style: CellStyle::default(),
        };
        let frame = RowFrame {
            text: "a".repeat(600),
            runs: vec![run(1, 100), run(1, 500)],
            cells: 2,
        };
        let update = shortened(RowUpdate::whole(3, &frame), 200);
        assert_eq!(
            update.runs,
            (0, 1),
            "the span that cannot be cut is dropped"
        );
        assert!(
            update.clear_tail,
            "the row no longer reaches the end of the line"
        );
        assert_eq!(update.row, 3);

        // A row every piece can already carry is left exactly as it is.
        let ordinary = RowFrame {
            text: "hello".into(),
            runs: vec![run(5, 5)],
            cells: 5,
        };
        let untouched = shortened(RowUpdate::whole(0, &ordinary), 200);
        assert_eq!(untouched.runs, (0, 1));
        assert!(!untouched.clear_tail);

        // The unstyled tail is one implicit span under the same bound, and it
        // travels only with a range that reaches the end of the runs.
        let tail = RowFrame {
            text: "x".repeat(900),
            runs: vec![run(1, 1)],
            cells: 2,
        };
        assert_eq!(shortened(RowUpdate::whole(0, &tail), 200).runs, (0, 0));
    }

    /// Nothing retransmits a screen, and the client emits deferred sequences
    /// only once one fully assembles, so a mark retired at encode time drops
    /// whatever a lost head or tail carried.
    #[test]
    fn deferred_sequences_are_retired_by_the_acknowledgement_not_by_the_encode() {
        let (mut attachment, _output) = framed_attachment(Framing::Stream, GRID);
        let mut log = DeferredOsc::new();
        log.feed(b"\x1b]52;c;aGk=\x07");
        let carried = attachment.owed_deferred(&log);
        assert_eq!(carried.len(), 1, "the clipboard write was never collected");

        attachment.sent(log.mark(), Instant::now());
        assert_eq!(
            attachment.owed_deferred(&log),
            carried,
            "a screen that reached the sink is not a screen the client assembled"
        );

        // The ledger has to be holding the screen this names, or there is
        // nothing for the acknowledgement to be about.
        let frame = test_frame(GRID, 0);
        let _ = paint_carrying(&mut attachment, &frame, carried.clone());
        attachment.sent(log.mark(), Instant::now());
        attachment.confirm(attachment.generation, attachment.version);

        assert!(
            attachment.owed_deferred(&log).is_empty(),
            "a client that confirmed the screen is still owed what it carried"
        );
    }
}
