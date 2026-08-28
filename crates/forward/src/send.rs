#![forbid(unsafe_code)]

//! The half that owes bytes. Three offsets are the whole repair: `base` is
//! what the peer confirmed, `next` is what has been on the wire at least once,
//! and `cursor` is where a repair walk stands.

use crate::timer::{Progress, Timer};
use crate::{
    Contradiction, FORWARD_WINDOW, INITIAL_WINDOW, MAX_FORWARD_CHUNK, SackRuns, Segment, as_len,
    as_off,
};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub(crate) struct Sender {
    /// Everything below it has been acknowledged and is gone.
    base: u64,
    buffer: VecDeque<u8>,
    /// One past the highest byte that has been transmitted at least once.
    next: u64,
    /// Where a repair walk stands. Equal to `next` when nothing is owed.
    cursor: u64,
    /// One past the last byte, so an acknowledgement above it means the peer
    /// saw the end and not merely every byte before it.
    fin: Option<u64>,
    fin_sent: bool,
    fin_acked: bool,
    /// What the peer last said it could take past `base`.
    window: u32,
    /// Absolute `[start, end)` ranges: ordered, disjoint, and inside what this
    /// side has sent. Replaced wholesale by each acknowledgement, since a stale
    /// run is a byte this side would never send again.
    held: Vec<(u64, u64)>,
    timer: Timer,
}

/// Mutually exclusive and in precedence order: a repair before fresh bytes,
/// fresh bytes before the end, and the probe only when there is nothing else.
enum Owed {
    Repair {
        off: u64,
        len: usize,
    },
    Fresh {
        off: u64,
        len: usize,
    },
    End {
        off: u64,
    },
    /// One byte from the head: the peer has just said it has nowhere to put
    /// bytes, and the answer to the probe is the only thing that ends the stall.
    Probe {
        off: u64,
    },
    Nothing,
}

impl Sender {
    pub(crate) fn new() -> Self {
        Self {
            base: 0,
            buffer: VecDeque::new(),
            next: 0,
            cursor: 0,
            fin: None,
            fin_sent: false,
            fin_acked: false,
            window: INITIAL_WINDOW,
            held: Vec::new(),
            timer: Timer::new(),
        }
    }

    fn end(&self) -> u64 {
        self.base + as_off(self.buffer.len())
    }

    pub(crate) fn writable(&self) -> usize {
        if self.fin.is_some() {
            return 0;
        }
        FORWARD_WINDOW - self.buffer.len()
    }

    pub(crate) fn write(&mut self, bytes: &[u8], now: Instant) -> usize {
        let take = self.writable().min(bytes.len());
        self.buffer.extend(&bytes[..take]);
        if take > 0 {
            // Armed on the write, not only on the send: a peer advertising a
            // closed window never acknowledges unprompted, so the probe that
            // reopens it would never be owed.
            self.timer.arm(now);
        }
        take
    }

    /// The end is not armed on a clock here: `transmitted` is what puts the
    /// retransmission timer behind it.
    pub(crate) fn finish(&mut self) {
        if self.fin.is_none() {
            self.fin = Some(self.end());
        }
    }

    pub(crate) fn poll_transmit(
        &mut self,
        now: Instant,
        budget: usize,
        out: &mut Vec<u8>,
    ) -> Option<Segment> {
        let budget = budget.min(MAX_FORWARD_CHUNK);
        if budget == 0 {
            return None;
        }
        let woken = self.timer.due(now);
        if woken {
            self.cursor = self.base;
            self.fin_sent = false;
            self.timer.expired();
        }
        match self.owed(woken, budget) {
            Owed::Repair { off, len } | Owed::Fresh { off, len } => self.fill(off, len, out),
            Owed::End { off } => self.fill(off, 0, out),
            Owed::Probe { off } => self.fill(off, 1, out),
            Owed::Nothing => None,
        }
    }

    fn owed(&self, woken: bool, budget: usize) -> Owed {
        let end = self.end();
        // A window the peer has since closed cannot withdraw credit it spent.
        if self.cursor < self.next {
            let off = self.unheld(self.cursor);
            if off < self.next {
                let stop = self.next_held(off).unwrap_or(self.next).min(self.next);
                return Owed::Repair {
                    off,
                    len: as_len(stop - off).min(budget),
                };
            }
        }
        let granted = self.base.saturating_add(u64::from(self.window));
        let limit = end.min(granted);
        if self.next < limit {
            return Owed::Fresh {
                off: self.next,
                len: as_len(limit - self.next).min(budget),
            };
        }
        if self.fin == Some(end) && self.next == end && !self.fin_sent && !self.fin_acked {
            return Owed::End { off: end };
        }
        // Without a probe, a lost window update is a deadlock both ends wait out.
        if woken && self.next == self.base && self.next < end {
            return Owed::Probe { off: self.base };
        }
        Owed::Nothing
    }

    /// A `VecDeque` is two slices and a segment is one, so a cut landing on the
    /// wrap is taken as the shorter piece rather than copied through a third.
    fn fill(&self, off: u64, len: usize, out: &mut Vec<u8>) -> Option<Segment> {
        let start = as_len(off - self.base);
        let (front, back) = self.buffer.as_slices();
        let taken = if start < front.len() {
            let take = len.min(front.len() - start);
            out.extend_from_slice(&front[start..start + take]);
            take
        } else {
            let start = start - front.len();
            let take = len.min(back.len().saturating_sub(start));
            out.extend_from_slice(&back[start..start + take]);
            take
        };
        let fin = self.fin == Some(off + as_off(taken));
        // An empty segment without the end says nothing, and a caller that sent
        // one would poll for it forever.
        (taken > 0 || fin).then_some(Segment {
            off,
            fin,
            len: taken,
        })
    }

    pub(crate) fn transmitted(&mut self, segment: Segment, now: Instant) {
        let end = segment.off + as_off(segment.len);
        let fresh = (end > self.next).then_some(end);
        self.next = self.next.max(end);
        self.cursor = self.cursor.max(end);
        if segment.fin {
            self.fin_sent = true;
        }
        self.timer.transmitted(fresh, now);
    }

    pub(crate) fn on_ack(
        &mut self,
        off: u64,
        window: u32,
        held: &SackRuns,
        now: Instant,
    ) -> Result<(), Contradiction> {
        if off < self.base {
            return Ok(());
        }
        let end = self.end();
        if off > self.base {
            let advance = as_len(off.min(end) - self.base);
            self.buffer.drain(..advance);
            self.base += as_off(advance);
            self.next = self.next.max(self.base);
            self.cursor = self.cursor.max(self.base);
            if self.fin.is_some_and(|fin| off > fin) {
                self.fin_acked = true;
            }
        }
        self.held.clear();
        for (start, run_end) in held.absolute(off) {
            if run_end > self.next {
                self.held.clear();
                return Err(Contradiction);
            }
            self.held.push((start, run_end));
        }
        self.window = window;
        let awaiting = self.awaiting_ack();
        // A repeat while the peer's window is shut says only that it is still
        // full, and a retransmission aimed at it is a flood.
        if self.timer.acknowledged(off, now, awaiting) == Progress::Stalled
            && window > 0
            && awaiting
        {
            self.cursor = self.base;
            self.fin_sent = false;
        }
        Ok(())
    }

    fn unheld(&self, off: u64) -> u64 {
        let mut off = off;
        for &(start, end) in &self.held {
            if off >= start && off < end {
                off = end;
            }
        }
        off
    }

    fn next_held(&self, off: u64) -> Option<u64> {
        self.held
            .iter()
            .map(|&(start, _)| start)
            .find(|&start| start > off)
    }

    fn awaiting_ack(&self) -> bool {
        self.base < self.end() || (self.fin.is_some() && !self.fin_acked)
    }

    pub(crate) fn is_done(&self) -> bool {
        self.fin.is_some() && self.fin_acked
    }

    pub(crate) fn deadline(&self, now: Instant) -> Option<Duration> {
        self.timer.remaining(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(sender: &mut Sender, now: Instant, budget: usize) -> Option<(Segment, Vec<u8>)> {
        let mut body = Vec::new();
        let segment = sender.poll_transmit(now, budget, &mut body)?;
        sender.transmitted(segment, now);
        Some((segment, body))
    }

    #[test]
    fn a_lost_head_is_repaired_and_the_tail_is_not_resent_from_scratch() {
        let start = Instant::now();
        let mut sender = Sender::new();
        sender.write(&vec![b'x'; 3000], start);
        let (first, _) = take(&mut sender, start, 1000).expect("a segment");
        let (second, _) = take(&mut sender, start, 1000).expect("another");
        assert_eq!((first.off, second.off), (0, 1000));
        // The peer acknowledges only the second: the head is what is missing.
        sender
            .on_ack(0, 65536, &SackRuns::EMPTY, start)
            .expect("a plain acknowledgement");
        sender
            .on_ack(0, 65536, &SackRuns::EMPTY, start)
            .expect("a plain acknowledgement");
        let (repair, _) = take(&mut sender, start, 1000).expect("the head again");
        assert_eq!(repair.off, 0, "a stalled ack repairs the head");
    }

    #[test]
    fn a_shut_window_holds_fresh_bytes_and_is_probed_rather_than_waited_out() {
        let start = Instant::now();
        let mut sender = Sender::new();
        sender.write(&vec![b'x'; 3000], start);
        let (first, _) = take(&mut sender, start, 1000).expect("the initial credit");
        assert_eq!(first.off, 0);
        // Everything sent so far is acknowledged, and the peer has no room.
        sender
            .on_ack(1000, 0, &SackRuns::EMPTY, start)
            .expect("a plain acknowledgement");
        let mut body = Vec::new();
        assert!(
            sender.poll_transmit(start, 1000, &mut body).is_none(),
            "a shut window stops fresh bytes"
        );
        let later = start + Duration::from_secs(5);
        let (probe, body) = take(&mut sender, later, 1000).expect("a probe");
        assert_eq!(probe.off, 1000);
        assert_eq!(
            (probe.len, body.len()),
            (1, 1),
            "a probe carries one byte to be answered, not a segment the peer has no room for"
        );
        let (again, body) = take(&mut sender, later + Duration::from_secs(5), 1000)
            .expect("the probe again, the window still shut");
        assert_eq!((again.off, again.len, body.len()), (1000, 1, 1));
    }

    #[test]
    fn an_end_rides_the_last_segment_or_gets_its_own_and_shuts_the_writer() {
        let now = Instant::now();
        // Declared after the last byte went: it owes a segment of its own.
        let mut late = Sender::new();
        late.write(b"abc", now);
        let (data, _) = take(&mut late, now, 1000).expect("the bytes");
        assert!(!data.fin);
        late.finish();
        let (fin, body) = take(&mut late, now, 1000).expect("the end");
        assert_eq!((fin.off, fin.len, fin.fin), (3, 0, true));
        assert!(body.is_empty());

        let mut early = Sender::new();
        early.write(b"abc", now);
        early.finish();
        let (data, body) = take(&mut early, now, 1000).expect("the bytes");
        assert!(data.fin, "the end rides the segment that reaches it");
        assert_eq!(body, b"abc");
        assert_eq!(early.write(b"d", now), 0, "nothing may be written past it");
        assert_eq!(early.writable(), 0);
    }

    #[test]
    fn an_acknowledged_end_finishes_the_half() {
        let now = Instant::now();
        let mut sender = Sender::new();
        sender.write(b"abc", now);
        sender.finish();
        take(&mut sender, now, 1000).expect("the bytes and the end");
        assert!(!sender.is_done());
        sender
            .on_ack(3, 65536, &SackRuns::EMPTY, now)
            .expect("a plain acknowledgement");
        assert!(!sender.is_done(), "an ack at the end is not an ack of it");
        sender
            .on_ack(4, 65536, &SackRuns::EMPTY, now)
            .expect("a plain acknowledgement");
        assert!(sender.is_done());
    }

    #[test]
    fn a_stale_acknowledgement_moves_nothing() {
        let now = Instant::now();
        let mut sender = Sender::new();
        sender.write(&vec![b'x'; 2000], now);
        take(&mut sender, now, 1000).expect("a segment");
        sender
            .on_ack(1000, 4096, &SackRuns::EMPTY, now)
            .expect("a plain acknowledgement");
        sender
            .on_ack(500, 1, &SackRuns::EMPTY, now)
            .expect("a plain acknowledgement");
        assert_eq!(sender.base, 1000);
        assert_eq!(sender.window, 4096, "a stale window is not a window");
    }
}
