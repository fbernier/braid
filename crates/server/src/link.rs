#![forbid(unsafe_code)]

//! A smoothed round-trip estimate, and the probe still in flight: the repaint
//! rate and the deadline that calls a peer dead both derive from it rather than
//! from a constant or from TCP.

use crate::{
    PING_CEILING, PING_DEAD_FLOOR, PING_DEAD_INTERVALS, PING_FLOOR, REPAINT_CEILING, REPAINT_FLOOR,
    RTT_SHIFT,
};
use std::time::{Duration, Instant};

/// A smoothed round-trip estimate, and the probe still in flight. Every pacing
/// interval on this attachment is derived from `srtt`.
pub(crate) struct LinkTiming {
    pub(crate) srtt: Option<Duration>,
    /// The probe token last sent, and when.
    pub(crate) outstanding: Option<(u64, Instant)>,
    next_token: u64,
    pub(crate) last_probe: Instant,
    /// When the client last answered anything.
    last_answer: Instant,
}

impl LinkTiming {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            srtt: None,
            outstanding: None,
            next_token: 1,
            last_probe: now,
            last_answer: now,
        }
    }

    /// The next probe token, if one is due.
    pub(crate) fn probe(&mut self, now: Instant) -> Option<u64> {
        if now.saturating_duration_since(self.last_probe) < self.ping_interval() {
            return None;
        }
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.last_probe = now;
        // Only the newest probe is timed: an answer to an older one measures
        // the queue it waited in rather than the link.
        self.outstanding = Some((token, now));
        Some(token)
    }

    pub(crate) fn answered(&mut self, token: u64) {
        self.last_answer = Instant::now();
        let Some((sent_token, sent_at)) = self.outstanding else {
            return;
        };
        if sent_token != token {
            return;
        }
        self.outstanding = None;
        let sample = sent_at.elapsed();
        // One eighth of the error, in whichever direction it falls: `Duration`
        // has no signed form, so the two halves are taken separately.
        self.srtt = Some(match self.srtt {
            None => sample,
            Some(srtt) => (srtt + sample.saturating_sub(srtt) / (1 << RTT_SHIFT))
                .saturating_sub(srtt.saturating_sub(sample) / (1 << RTT_SHIFT)),
        });
    }

    /// How long a screen must wait before the next one is worth sending.
    pub(crate) fn repaint_interval(&self) -> Duration {
        self.srtt
            .map_or(REPAINT_CEILING.min(Duration::from_millis(33)), |srtt| {
                (srtt / 2).clamp(REPAINT_FLOOR, REPAINT_CEILING)
            })
    }

    /// How long an unanswered screen holds the next one back.
    pub(crate) fn ack_timeout(&self) -> Duration {
        self.srtt
            .map_or(REPAINT_CEILING, |srtt| srtt * 2)
            .clamp(REPAINT_CEILING, Duration::from_secs(2))
    }

    /// How often this attachment is probed, and how long the client is told it
    /// may wait for the next one.
    pub(crate) fn ping_interval(&self) -> Duration {
        self.srtt.map_or(PING_CEILING, |srtt| {
            (srtt * 2).clamp(PING_FLOOR, PING_CEILING)
        })
    }

    /// The interval as the wire carries it. [`PING_CEILING`] is two seconds, so
    /// the saturation here is unreachable rather than a decision.
    pub(crate) fn interval_ms(&self) -> u16 {
        u16::try_from(self.ping_interval().as_millis()).unwrap_or(u16::MAX)
    }

    pub(crate) fn is_dead(&self, now: Instant) -> bool {
        let deadline = (self.ping_interval() * PING_DEAD_INTERVALS).max(PING_DEAD_FLOOR);
        now.saturating_duration_since(self.last_answer) > deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// The client's patience is derived from a number this side ships, so the
    /// pacing has to track the link and stay inside what the field can carry.
    #[test]
    fn the_probe_interval_is_paced_by_the_round_trip() {
        let mut link = LinkTiming::new();
        // Nothing measured yet: the most patient interval.
        assert_eq!(link.ping_interval(), PING_CEILING);

        link.srtt = Some(Duration::from_millis(10));
        assert_eq!(link.ping_interval(), PING_FLOOR);
        link.srtt = Some(Duration::from_millis(400));
        assert_eq!(link.ping_interval(), Duration::from_millis(800));
        assert_eq!(link.interval_ms(), 800);
        link.srtt = Some(Duration::from_secs(5));
        assert_eq!(link.ping_interval(), PING_CEILING);

        // Five intervals or the floor, whichever is longer: a LAN must not
        // call a scheduling hiccup a death, and it must not wait out twenty
        // seconds of a session that is already gone either.
        let now = Instant::now();
        link.srtt = Some(Duration::from_millis(10));
        link.last_answer = now
            .checked_sub(PING_DEAD_FLOOR / 2)
            .expect("the test clock is not at the epoch");
        assert!(!link.is_dead(now));
        link.last_answer = now
            .checked_sub(PING_DEAD_FLOOR * 2)
            .expect("the test clock is not at the epoch");
        assert!(link.is_dead(now));
    }
}
