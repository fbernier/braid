#![forbid(unsafe_code)]

//! When the head of a forwarded stream is owed another copy: a smoothed round
//! trip, Karn's rule and one fast retransmit per stalled acknowledgement, the
//! shape the client's journal uses, keyed by byte offset.

use std::time::{Duration, Instant};

/// What a sender waits before its first retransmission, having measured
/// nothing.
const INITIAL: Duration = Duration::from_millis(250);
/// The floor keeps a fast link from repeating a segment still in flight; the
/// ceiling keeps a quiet link from waiting minutes to find out.
const MIN: Duration = Duration::from_millis(50);
const MAX: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    Advanced,
    /// First repeat since it last moved. A cumulative acknowledgement cannot
    /// advance past the oldest byte the peer is missing, so this is the peer
    /// saying the head did not arrive.
    Stalled,
    Repeated,
}

pub(crate) struct Timer {
    srtt: Option<Duration>,
    /// One past the last byte of the segment being timed, and when it went.
    /// Dropped the moment that segment is sent again: a sample from a
    /// retransmission cannot say which copy was acknowledged (Karn's rule).
    sample: Option<(u64, Instant)>,
    /// `None` while nothing is owed.
    waiting: Option<Instant>,
    attempts: u32,
    acked: u64,
    retried: bool,
}

impl Timer {
    pub(crate) fn new() -> Self {
        Self {
            srtt: None,
            sample: None,
            waiting: None,
            attempts: 0,
            acked: 0,
            retried: false,
        }
    }

    /// Not restarted per segment: a sender filling a window would push the
    /// deadline out with every frame and never retransmit the lost head.
    pub(crate) fn arm(&mut self, now: Instant) {
        if self.waiting.is_none() {
            self.waiting = Some(now);
        }
    }

    pub(crate) fn due(&self, now: Instant) -> bool {
        self.waiting
            .is_some_and(|since| now.saturating_duration_since(since) >= self.interval())
    }

    pub(crate) fn remaining(&self, now: Instant) -> Option<Duration> {
        let since = self.waiting?;
        Some(
            self.interval()
                .saturating_sub(now.saturating_duration_since(since)),
        )
    }

    pub(crate) fn expired(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.waiting = None;
        self.sample = None;
    }

    /// Timed only when it is the first copy of bytes never sent before.
    pub(crate) fn transmitted(&mut self, fresh_end: Option<u64>, now: Instant) {
        self.arm(now);
        if let Some(end) = fresh_end
            && self.sample.is_none()
        {
            self.sample = Some((end, now));
        }
    }

    pub(crate) fn acknowledged(&mut self, off: u64, now: Instant, owed: bool) -> Progress {
        if let Some((end, sent)) = self.sample
            && off >= end
        {
            self.observe(now.saturating_duration_since(sent));
            self.sample = None;
        }
        let progress = if off > self.acked {
            self.acked = off;
            self.attempts = 0;
            self.retried = false;
            Progress::Advanced
        } else if self.retried {
            Progress::Repeated
        } else {
            self.retried = true;
            Progress::Stalled
        };
        self.waiting = owed.then_some(now);
        if !owed {
            self.sample = None;
        }
        progress
    }

    /// At one eighth, as TCP does.
    fn observe(&mut self, sample: Duration) {
        self.srtt = Some(match self.srtt {
            None => sample,
            Some(srtt) => srtt * 7 / 8 + sample / 8,
        });
    }

    /// Two round trips, doubled for each attempt that went unanswered.
    fn interval(&self) -> Duration {
        let base = self.srtt.map_or(INITIAL, |srtt| srtt * 2);
        base.saturating_mul(1_u32 << self.attempts.min(5))
            .clamp(MIN, MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_owed_is_never_due() {
        let timer = Timer::new();
        assert!(!timer.due(Instant::now() + Duration::from_mins(1)));
    }

    #[test]
    fn the_wait_is_not_restarted_per_segment() {
        let start = Instant::now();
        let mut timer = Timer::new();
        timer.transmitted(Some(10), start);
        timer.transmitted(Some(20), start + Duration::from_millis(200));
        assert!(
            timer.due(start + INITIAL),
            "the head's deadline is the head's, not the newest frame's"
        );
    }

    #[test]
    fn a_repeat_stalls_once_then_only_repeats() {
        let now = Instant::now();
        let mut timer = Timer::new();
        timer.transmitted(Some(10), now);
        assert_eq!(timer.acknowledged(5, now, true), Progress::Advanced);
        assert_eq!(timer.acknowledged(5, now, true), Progress::Stalled);
        assert_eq!(timer.acknowledged(5, now, true), Progress::Repeated);
        assert_eq!(timer.acknowledged(6, now, true), Progress::Advanced);
    }

    #[test]
    fn a_sample_is_not_taken_from_a_retransmission() {
        let start = Instant::now();
        let mut timer = Timer::new();
        timer.transmitted(Some(10), start);
        timer.expired();
        // The resend carries no fresh bytes, so nothing is timed by it.
        timer.transmitted(None, start + Duration::from_millis(250));
        timer.acknowledged(10, start + Duration::from_millis(300), false);
        assert!(
            timer.srtt.is_none(),
            "an ack that could have covered either copy is not a sample"
        );
    }

    #[test]
    fn the_interval_backs_off_and_is_bounded() {
        let mut timer = Timer::new();
        let first = timer.interval();
        for _ in 0..12 {
            timer.expired();
        }
        assert!(timer.interval() > first);
        assert_eq!(timer.interval(), MAX);
    }
}
