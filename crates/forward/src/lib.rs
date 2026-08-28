#![forbid(unsafe_code)]

//! Per-stream retransmission for forwarded TCP connections, over a datagram
//! transport that provides none. Forward payload stays out of the ordered
//! `CmdSeq` stream, where a lost frame would stall every keystroke behind it.

use std::time::{Duration, Instant};

mod recv;
mod send;
mod timer;

use recv::Receiver;
use send::Sender;

pub use braid_proto::{MAX_ACK_RUNS, MAX_FORWARD_CHUNK, SackRun, SackRuns};

/// Bytes one direction may hold unacknowledged: retransmission buffer,
/// receive buffer and advertised window are one number seen from three sides.
pub const FORWARD_WINDOW: usize = 256 * 1024;

/// Segments held past a gap before the receiver stops holding any, bounding
/// tiny segments the way [`FORWARD_WINDOW`] bounds their bytes.
pub const MAX_HELD_SEGMENTS: usize = 256;

/// A segment's worth of window, asserted equal to the wire bound rather than
/// cast down from it.
pub(crate) const CHUNK_WINDOW: u32 = 32 * 1024;
const _: () = assert!(CHUNK_WINDOW as usize == MAX_FORWARD_CHUNK);

/// One segment, so the first byte moves before any window update is sent.
const INITIAL_WINDOW: u32 = CHUNK_WINDOW;

/// The peer declared two ends for one half, or payload past an end. Nothing
/// repairs it, so the caller resets the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contradiction;

impl std::fmt::Display for Contradiction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a forwarded stream contradicted its own end")
    }
}

impl std::error::Error for Contradiction {}

/// One piece of a forwarded stream, handed back to [`Stream::transmitted`]
/// rather than recorded by the poll: a sink that refuses the frame must leave
/// the stream owing exactly what it owed before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub off: u64,
    /// The end occupies the offset one past the last byte, as TCP's does.
    pub fin: bool,
    pub len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    /// Every byte below this has been placed.
    pub off: u64,
    /// Room past `off`.
    pub window: u32,
    /// Runs above the gap at `off` that arrived anyway, so a repair is not a
    /// go-back-N.
    pub held: SackRuns,
}

/// One forwarded connection's two halves. Both ends run the same type: the
/// daemon's side of a `-L` tunnel is the client's with the sockets swapped.
pub struct Stream {
    send: Sender,
    recv: Receiver,
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream {
    pub fn new() -> Self {
        Self {
            send: Sender::new(),
            recv: Receiver::new(),
        }
    }

    /// Bytes the local socket may hand over. Zero is where the caller stops
    /// reading its socket, turning a stalled forward into backpressure.
    pub fn writable(&self) -> usize {
        self.send.writable()
    }

    pub fn write(&mut self, bytes: &[u8], now: Instant) -> usize {
        self.send.write(bytes, now)
    }

    pub fn finish(&mut self) {
        self.send.finish();
    }

    /// `budget` is what the current transport can seal into one frame.
    pub fn poll_transmit(
        &mut self,
        now: Instant,
        budget: usize,
        out: &mut Vec<u8>,
    ) -> Option<Segment> {
        self.send.poll_transmit(now, budget, out)
    }

    pub fn transmitted(&mut self, segment: Segment, now: Instant) {
        self.send.transmitted(segment, now);
    }

    /// A peer naming bytes this side never sent has contradicted the stream.
    pub fn on_ack(
        &mut self,
        off: u64,
        window: u32,
        held: &SackRuns,
        now: Instant,
    ) -> Result<(), Contradiction> {
        self.send.on_ack(off, window, held, now)
    }

    pub fn on_data(&mut self, off: u64, fin: bool, bytes: &[u8]) -> Result<(), Contradiction> {
        self.recv.on_data(off, fin, bytes)
    }

    pub fn poll_ack(&mut self) -> Option<Ack> {
        self.recv.poll_ack()
    }

    /// Two slices, as a `VecDeque` holds them; either may be empty.
    pub fn readable(&self) -> (&[u8], &[u8]) {
        self.recv.readable()
    }

    pub fn consume(&mut self, n: usize) {
        self.recv.consume(n);
    }

    /// An end is a byte position, not an event, so this stays false while data
    /// it follows is still in hand.
    pub fn peer_finished(&self) -> bool {
        self.recv.finished()
    }

    /// Both halves closed and nothing owed: the caller may forget the stream.
    pub fn is_done(&self) -> bool {
        self.send.is_done() && self.recv.finished() && self.recv.readable_len() == 0
    }

    pub fn deadline(&self, now: Instant) -> Option<Duration> {
        self.send.deadline(now)
    }
}

/// Saturating rather than wrapping: every length here is bounded by
/// [`FORWARD_WINDOW`], so the saturation is unreachable.
pub(crate) fn as_off(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

pub(crate) fn as_len(off: u64) -> usize {
    usize::try_from(off).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link that delivers everything, immediately, in order.
    fn pump(from: &mut Stream, to: &mut Stream, now: Instant, budget: usize) {
        let mut body = Vec::new();
        while let Some(segment) = from.poll_transmit(now, budget, &mut body) {
            to.on_data(segment.off, segment.fin, &body)
                .expect("a stream does not contradict itself");
            from.transmitted(segment, now);
            if let Some(ack) = to.poll_ack() {
                from.on_ack(ack.off, ack.window, &ack.held, now)
                    .expect("a stream does not contradict itself");
            }
            body.clear();
        }
    }

    #[test]
    fn a_stream_carries_what_was_written_and_ends_at_a_byte_position() {
        let now = Instant::now();
        let (mut a, mut b) = (Stream::new(), Stream::new());
        assert_eq!(a.write(b"hello world", now), 11);
        pump(&mut a, &mut b, now, 1138);
        assert!(!b.peer_finished(), "the bytes are not the end");
        a.finish();
        pump(&mut a, &mut b, now, 1138);
        assert!(b.peer_finished());
        let (front, back) = b.readable();
        assert_eq!([front, back].concat(), b"hello world");
    }

    #[test]
    fn an_end_that_overtakes_its_data_still_ends_at_the_right_byte() {
        let mut b = Stream::new();
        b.on_data(3, true, b"").expect("a legal end");
        assert!(!b.peer_finished(), "an end past a gap is not an end yet");
        b.on_data(0, false, b"abc").expect("the bytes behind it");
        assert!(b.peer_finished());
        assert_eq!(b.readable().0, b"abc");
    }

    #[test]
    fn a_stream_that_contradicts_its_own_end_is_rejected() {
        // A second, different end; then payload past the end already declared.
        for (off, fin, bytes) in [(0_u64, true, &b"abcd"[..]), (3, false, &b"d"[..])] {
            let mut b = Stream::new();
            b.on_data(0, true, b"abc").expect("a legal end at 3");
            assert_eq!(b.on_data(off, fin, bytes), Err(Contradiction));
        }
    }

    #[test]
    fn a_poll_that_is_not_transmitted_still_owes_the_bytes() {
        let now = Instant::now();
        let mut a = Stream::new();
        a.write(b"payload", now);
        let mut first = Vec::new();
        let one = a.poll_transmit(now, 1138, &mut first).expect("a segment");
        let mut second = Vec::new();
        let two = a
            .poll_transmit(now, 1138, &mut second)
            .expect("the same one");
        assert_eq!(one, two, "a refused frame leaves the stream where it was");
        assert_eq!(first, second);
    }

    #[test]
    fn a_writer_stops_at_the_window() {
        let now = Instant::now();
        let mut a = Stream::new();
        let bulk = vec![0_u8; FORWARD_WINDOW + 4096];
        assert_eq!(a.write(&bulk, now), FORWARD_WINDOW);
        assert_eq!(a.writable(), 0);
    }
}
