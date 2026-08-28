#![forbid(unsafe_code)]

//! The receiving half: the deadline a silent link is judged by, the frames a
//! transport hands up, and the chunks that arrived ahead of what they follow.

use crate::dgram::{DatagramLink, DatagramReader, DatagramSink};
use crate::outbound::FrameSink;
use crate::state::ReconnectState;
use crate::terminal::Shared;
use braid_proto::{
    ByteOff, CmdSeq, DatagramOffer, InputCue, MAX_FRAME, MAX_OUTPUT_CHUNK, ServerMessage, Version,
    read_frame_into,
};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::process::ChildStdout;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Silence meaning the link is gone, until [`ServerMessage::Ping`] says how
/// often the server probes. With no deadline the only thing that notices a
/// black-holed connection is TCP's retransmit budget, in minutes.
pub(crate) const LINK_TIMEOUT: Duration = Duration::from_secs(10);

/// The floor stops an implausibly tight advertised interval from reconnecting
/// on jitter; the ceiling stops a slack one restoring a ten-second wait.
pub(crate) const MIN_LINK_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const MAX_LINK_TIMEOUT: Duration = Duration::from_secs(15);

/// Three unanswered probes, clamped: the server owns pacing, the client patience.
pub(crate) fn silence_deadline(interval_ms: u16) -> Duration {
    Duration::from_millis(3 * u64::from(interval_ms)).clamp(MIN_LINK_TIMEOUT, MAX_LINK_TIMEOUT)
}

/// How long a resume may wait. `ConnectTimeout` covers the TCP SYN alone, and
/// authentication, a hanging `brd --server` and a stalled sshd are past it;
/// finite because `Ctrl-] .` is polled only between attempts.
pub(crate) const RESUME_TIMEOUT: Duration = Duration::from_secs(20);

/// A deadline the reader polls against, which the thread reading `Ping` moves.
/// One atomic: the reader loop is its only writer and its only reader.
#[derive(Clone)]
pub(crate) struct Deadline(Arc<AtomicU64>);

impl Deadline {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self(Arc::new(AtomicU64::new(Self::millis(timeout))))
    }

    pub(crate) fn set(&self, timeout: Duration) {
        self.0.store(Self::millis(timeout), Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Relaxed))
    }

    fn millis(timeout: Duration) -> u64 {
        u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
    }
}

/// Reports silence past the deadline as `TimedOut`, which the session loop
/// already reads as transport loss. [`Self::new`] sets the descriptor
/// non-blocking, which the read below rests on and is why it is the only
/// constructor.
pub(crate) struct DeadlineReader<R> {
    inner: R,
    timeout: Deadline,
}

impl<R: AsFd> DeadlineReader<R> {
    pub(crate) fn new(inner: R, timeout: Deadline) -> io::Result<Self> {
        let flags = rustix::fs::fcntl_getfl(&inner)?;
        rustix::fs::fcntl_setfl(&inner, flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self { inner, timeout })
    }

    /// Still non-blocking: the session loop wraps it in one of these again.
    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsFd + Read> Read for DeadlineReader<R> {
    /// Read first, poll only when there is nothing to read: polling first
    /// costs two syscalls on every read, and the extra `EAGAIN` a quiet link
    /// pays happens before this thread parks, never on the latency path.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.timeout.get();
        let deadline = rustix::fs::Timespec {
            tv_sec: timeout.as_secs().try_into().unwrap_or(i64::MAX),
            tv_nsec: timeout.subsec_nanos().into(),
        };
        loop {
            match self.inner.read(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
            // Built here, so a read that answered straight away pays nothing.
            let mut fds = [rustix::event::PollFd::new(
                &self.inner,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut fds, Some(&deadline)) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
                // Ready, or interrupted before it could say: both go round again.
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// Where the byte stream stands after a chunk, or `None` when the chunk does
/// not belong at the position this client holds. The refusal is a repaint,
/// never an error: ending the session over a skew destroys one the very next
/// message would have fixed.
pub(crate) fn place_output(expected: ByteOff, off: ByteOff, len: usize) -> Option<ByteOff> {
    if off != expected {
        return None;
    }
    expected.checked_add(len)
}

/// How far the stream moves before the client restates the window: a quarter
/// of the server's outstanding-byte bound, so it is reopened four times over.
pub(crate) const CONSUMED_STRIDE: usize = 64 * 1024;

/// Output chunks that arrived ahead of the byte they follow.
///
/// Unbuffered, one lost datagram makes *every* chunk behind it ask for a whole
/// screen - a repaint storm answering a single drop, on the transport whose
/// whole claim is loss tolerance. Bounded by [`REORDER_PIECES`],
/// [`REORDER_BYTES`] and [`reorder_deadline`], which is the only one of the
/// three that can decide once arrivals stop.
#[derive(Default)]
pub(crate) struct Reorder {
    held: Vec<(ByteOff, Vec<u8>, InputCue, Option<CmdSeq>)>,
    bytes: usize,
    /// `None` exactly when nothing is held, so the age measured is this gap's.
    since: Option<Instant>,
}

/// Chunks held past a gap before it is called a loss.
const REORDER_PIECES: usize = 32;

/// Bytes held past a gap, whatever the piece count says.
const REORDER_BYTES: usize = 256 * 1024;

/// The floor stops a LAN's sub-millisecond estimate calling jitter a loss; the
/// ceiling stops a satellite holding the terminal still for seconds.
pub(crate) const MIN_REORDER_WAIT: Duration = Duration::from_millis(50);
pub(crate) const MAX_REORDER_WAIT: Duration = Duration::from_secs(1);

/// How long a gap is given to close before the chunk it waits on is lost.
/// Reordering is the difference between two paths' latencies and so is under
/// one round trip, and nothing below this layer retransmits.
pub(crate) fn reorder_deadline(srtt: Option<Duration>) -> Duration {
    srtt.map_or(MAX_REORDER_WAIT, |srtt| {
        (srtt * 2).clamp(MIN_REORDER_WAIT, MAX_REORDER_WAIT)
    })
}

impl Reorder {
    /// Hold a chunk that starts past `expected`.
    pub(crate) fn hold(
        &mut self,
        off: ByteOff,
        bytes: Vec<u8>,
        cue: InputCue,
        echo_ack: Option<CmdSeq>,
        now: Instant,
    ) {
        // A duplicate is a datagram the replay window let through under a fresh
        // packet number; holding two copies of one offset double-applies it.
        if self.held.iter().any(|(held, ..)| *held == off) {
            return;
        }
        self.bytes += bytes.len();
        self.since.get_or_insert(now);
        self.held.push((off, bytes, cue, echo_ack));
        self.held.sort_by_key(|(off, ..)| off.get());
    }

    /// Whether the gap has stopped looking like a reorder. The clock is the
    /// bound that matters: the other two can only decide while chunks keep
    /// arriving, and a datagram lost at the end of a burst produces none.
    pub(crate) fn lost(&self, now: Instant, deadline: Duration) -> bool {
        self.held.len() >= REORDER_PIECES
            || self.bytes >= REORDER_BYTES
            || self
                .since
                .is_some_and(|since| now.saturating_duration_since(since) >= deadline)
    }

    /// The chunk that continues the stream at `expected`, if it is held. Also
    /// drops what is behind it, which is what a screen's jump in `next_off`
    /// leaves stranded.
    pub(crate) fn take(
        &mut self,
        expected: ByteOff,
    ) -> Option<(Vec<u8>, InputCue, Option<CmdSeq>)> {
        self.held.retain(|(off, bytes, ..)| {
            off.get().saturating_add(bytes.len() as u64) > expected.get()
        });
        let at = self.held.iter().position(|(off, ..)| *off == expected);
        let taken = at.map(|at| {
            let (_, bytes, cue, echo_ack) = self.held.remove(at);
            (bytes, cue, echo_ack)
        });
        self.bytes = self.held.iter().map(|(_, bytes, ..)| bytes.len()).sum();
        // A stamp kept past a closed gap would age the next one wrongly.
        if self.held.is_empty() {
            self.since = None;
        }
        taken
    }

    pub(crate) fn clear(&mut self) {
        self.held.clear();
        self.bytes = 0;
        self.since = None;
    }
}

/// Where this session's frames arrive from. The transports differ in what a
/// frame *is* - a stream re-frames bytes, a datagram carries exactly one.
pub(crate) enum Inbound {
    Ssh(io::BufReader<DeadlineReader<ChildStdout>>),
    Datagram(DatagramReader),
}

impl Inbound {
    /// Buffered outside the deadline, which holds the descriptor: every frame
    /// otherwise costs two unbuffered `read(2)`s. Sized to a whole frame, or
    /// the default cuts every full-size `Output` frame into eight reads.
    pub(crate) fn ssh(output: ChildStdout, timeout: Deadline) -> io::Result<Self> {
        Ok(Self::Ssh(io::BufReader::with_capacity(
            MAX_OUTPUT_CHUNK + 4,
            DeadlineReader::new(output, timeout)?,
        )))
    }

    /// The next frame, calling `park` if this is about to wait for one.
    ///
    /// The client must never sleep holding bytes the terminal has not been
    /// shown, and must not pay a write for a frame already in hand - which an
    /// unconditional flush does, seventeen times for a repaint's seventeen
    /// datagrams. Only the reader about to wait can tell those apart.
    fn read_frame_into(
        &mut self,
        payload: &mut Vec<u8>,
        park: &mut dyn FnMut(),
    ) -> Result<(), braid_proto::DecodeError> {
        match self {
            // A whole frame in the buffer never touches the descriptor.
            Self::Ssh(stream) => {
                if !whole_frame(stream.buffer()) {
                    park();
                }
                read_frame_into(stream, payload, MAX_FRAME)
            }
            // A readable socket is not a frame in hand: this reader drops
            // acknowledgements and keep-alives without handing anything up, so
            // it is the one that knows when it is about to wait.
            Self::Datagram(reader) => reader.read_frame_into(payload, park),
        }
    }
}

/// Whether `buffered` already holds a whole frame, length prefix and all.
fn whole_frame(buffered: &[u8]) -> bool {
    buffered.first_chunk::<4>().is_some_and(|header| {
        usize::try_from(u32::from_be_bytes(*header))
            .is_ok_and(|length| buffered.len() - 4 >= length)
    })
}

/// The next frame, with the terminal handed what it holds before any wait.
///
/// The flush swallows its own failure: this runs inside a reader with no error
/// of its own to carry, and a terminal that will not take bytes ends the
/// session at the next write. Unconditional because an empty
/// [`io::BufWriter`] issues no syscall.
pub(crate) fn next_frame<W: Write>(
    inbound: &mut Inbound,
    payload: &mut Vec<u8>,
    display: &Shared<W>,
) -> Result<(), braid_proto::DecodeError> {
    inbound.read_frame_into(payload, &mut || {
        if let Ok(mut display) = display.lock() {
            let _ = display.flush();
        }
    })
}

/// The next frame for a client with no terminal under it: a forward-only
/// client holds nothing on its way to a screen, so there is nothing to flush.
pub(crate) fn next_forward_frame(
    inbound: &mut Inbound,
    payload: &mut Vec<u8>,
) -> Result<(), braid_proto::DecodeError> {
    inbound.read_frame_into(payload, &mut || {})
}

/// Three tries under a second: enough to survive the first `Resume` being
/// dropped, short enough that blocked UDP falls back without a visible pause.
pub(crate) const DATAGRAM_PROBES: u32 = 3;
pub(crate) const DATAGRAM_PROBE_INTERVAL: Duration = Duration::from_millis(300);

/// Whether this process may take up a datagram offer.
///
/// The datagram path has no configuration otherwise: it is taken when it works
/// and skipped when it does not. The escape hatch exists for a link that
/// mangles UDP without dropping it, and for harnesses measuring this client
/// against a *delayed* `ssh` pipe. Read once, at the edge.
pub(crate) fn datagrams_wanted() -> bool {
    std::env::var_os("BRD_NO_DATAGRAM").is_none()
}

/// Take the daemon up on its offer, or leave the session where it is. The
/// `Resume` carries `*CLIENT_ID`, which makes the daemon *replace* the
/// attachment `ssh` holds rather than open a second one. A failure costs the
/// probes and nothing else, and prints nothing.
pub(crate) fn take_offer(
    offer: &DatagramOffer,
    state: &ReconnectState,
    deadline: &Deadline,
) -> Option<(DatagramSink, DatagramReader, Version)> {
    let link = DatagramLink::open(offer)?;
    let (sink, mut reader) = link.split(deadline.clone())?;
    // A handshake frame: the datagram link negotiates its own version.
    let resume = state
        .resume_message(CmdSeq::first())
        .encode(Version::LOCAL)
        .ok()?;
    // The session's own deadline, borrowed: this runs before the loop that
    // reads against it, so nothing else is waiting on the number meanwhile.
    deadline.set(DATAGRAM_PROBE_INTERVAL);
    let mut payload = Vec::new();
    let mut answered = None;
    for _ in 0..DATAGRAM_PROBES {
        if !sink.send(resume.clone()) {
            break;
        }
        if reader.read_frame_into(&mut payload, &mut || {}).is_err() {
            continue;
        }
        // Either establishment message, because the one that arrives names the
        // session's kind: a forward-only session has no grid to state.
        answered = match ServerMessage::decode(&payload, Version::LOCAL) {
            Ok(
                ServerMessage::Hello { version, .. } | ServerMessage::HelloForward { version, .. },
            ) => Some(version),
            _ => None,
        };
        break;
    }
    deadline.set(LINK_TIMEOUT);
    answered.map(|version| (sink, reader, version))
}
