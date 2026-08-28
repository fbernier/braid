#![forbid(unsafe_code)]

use braid_proto::ByteOff;

/// Recent output, kept so a resuming client can be given the bytes it missed.
///
/// Eviction is not reported: [`BacklogRing::replay_from`] already refuses an
/// offset the ring no longer holds.
///
/// The buffer grows into `capacity` rather than starting there: eight megabytes
/// a session, touched at `Hello`, is half a gigabyte of resident memory across
/// a full daemon before a shell has printed anything.
pub struct BacklogRing {
    /// The ring's modulus is this length, not the ceiling.
    buf: Vec<u8>,
    capacity: usize,
    base: ByteOff,
    len: usize,
    head: usize,
}

/// Bytes the ring claims on the first push. One PTY read is 64 KiB, so a
/// session printing one prompt does not double four times to hold it.
const FLOOR: usize = 16 * 1024;

impl BacklogRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::new(),
            capacity,
            base: ByteOff::zero(),
            len: 0,
            head: 0,
        }
    }

    /// Called before the eviction arithmetic, never after: a ring that dropped
    /// history it had the capacity to keep would answer `replay_from` with
    /// `None` for an offset the session was still holding.
    fn grow_for(&mut self, extra: usize) {
        let needed = self.len.saturating_add(extra).min(self.capacity);
        if needed <= self.buf.len() {
            return;
        }
        let mut size = self.buf.len().max(FLOOR);
        while size < needed {
            size = size.saturating_mul(2);
        }
        let mut grown = vec![0; size.min(self.capacity)];
        // Linearised on the way across, which is what lets `head` restart at
        // zero: a ring copied verbatim into a longer buffer has its wrap in the
        // wrong place and reads back as history nobody wrote.
        let first = (self.buf.len() - self.head).min(self.len);
        grown[..first].copy_from_slice(&self.buf[self.head..self.head + first]);
        grown[first..self.len].copy_from_slice(&self.buf[..self.len - first]);
        self.buf = grown;
        self.head = 0;
    }

    pub fn push(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }
        if self.capacity == 0 {
            self.base = self.base.checked_add(input.len()).unwrap_or(self.base);
            return;
        }
        self.grow_for(input.len());
        let skip = input.len().saturating_sub(self.buf.len());
        let bytes = &input[skip..];
        let overwrite = self
            .len
            .saturating_add(bytes.len())
            .saturating_sub(self.buf.len());
        if overwrite > 0 {
            self.head = (self.head + overwrite) % self.buf.len();
            self.len -= overwrite;
        }
        self.base = self.base.checked_add(skip + overwrite).unwrap_or(self.base);
        let tail = (self.head + self.len) % self.buf.len();
        let first = bytes.len().min(self.buf.len() - tail);
        self.buf[tail..tail + first].copy_from_slice(&bytes[..first]);
        if first < bytes.len() {
            self.buf[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        }
        self.len += bytes.len();
    }

    pub fn replay_from(&self, off: ByteOff) -> Option<(&[u8], &[u8])> {
        let start = usize::try_from(off.get().checked_sub(self.base.get())?).ok()?;
        if start > self.len {
            return None;
        }
        if self.buf.is_empty() {
            // Nothing pushed yet, so the base is the only offset this holds and
            // what it holds there is nothing.
            return (self.capacity > 0).then_some((&[][..], &[][..]));
        }
        let physical = (self.head + start) % self.buf.len();
        let first_len = (self.len - start).min(self.buf.len() - physical);
        let second_len = self.len - start - first_len;
        Some((
            &self.buf[physical..physical + first_len],
            &self.buf[..second_len],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_replay_is_contiguous_in_two_slices() {
        let mut ring = BacklogRing::new(5);
        ring.push(b"abc");
        ring.push(b"def");
        let (a, b) = ring
            .replay_from(ByteOff::zero().checked_add(2).unwrap())
            .unwrap();
        assert_eq!([a, b].concat(), b"cdef");
        // The first byte has been overwritten: an offset the ring no longer
        // holds is refused rather than answered with the wrong bytes.
        assert!(ring.replay_from(ByteOff::zero()).is_none());
    }

    /// Eight megabytes a session, taken at `Hello`, is half a gigabyte of
    /// resident memory across a full daemon before anything has printed.
    #[test]
    fn a_ring_claims_nothing_until_something_is_pushed_into_it() {
        let mut ring = BacklogRing::new(8 * 1024 * 1024);
        assert_eq!(ring.buf.len(), 0);
        // A session that has produced nothing has missed nothing, which is not
        // the same answer as an offset the ring evicted.
        assert_eq!(ring.replay_from(ByteOff::zero()), Some((&[][..], &[][..])));
        ring.push(b"hello");
        assert_eq!(ring.buf.len(), FLOOR);
    }

    /// Growth is what keeps eviction a property of the ceiling rather than of
    /// whatever the ring happened to have claimed when the burst arrived.
    #[test]
    fn a_ring_doubles_into_its_ceiling_without_evicting_what_it_could_hold() {
        let mut ring = BacklogRing::new(4 * FLOOR);
        let chunk = vec![b'x'; FLOOR];
        for _ in 0..4 {
            ring.push(&chunk);
        }
        assert_eq!(ring.buf.len(), 4 * FLOOR);
        let (first, second) = ring.replay_from(ByteOff::zero()).expect("nothing evicted");
        assert_eq!(first.len() + second.len(), 4 * FLOOR);
        // One past the ceiling, and only then does the oldest byte go.
        ring.push(b"y");
        assert!(ring.replay_from(ByteOff::zero()).is_none());
        assert_eq!(ring.buf.len(), 4 * FLOOR);
    }

    /// Growth moves every byte the ring was holding, so an offset a resume
    /// names before one is still answered with the same bytes after it.
    #[test]
    fn history_written_before_a_growth_reads_back_unchanged_after_it() {
        let mut ring = BacklogRing::new(4 * FLOOR);
        ring.push(b"first");
        ring.push(&vec![b'x'; FLOOR]);
        assert_eq!(ring.buf.len(), 2 * FLOOR);
        let (head, wrapped) = ring
            .replay_from(ByteOff::zero())
            .expect("the ceiling has room for all of it");
        assert!(wrapped.is_empty(), "a ring that grew is never wrapped");
        assert_eq!(&head[..5], b"first");
    }
}
