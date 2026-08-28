#![forbid(unsafe_code)]

//! How much may be in flight, and how fast it may leave: New Reno in RFC 9002's
//! shape, plus a token-bucket pacer and an RFC 9406-style delay trigger, both
//! because a loss-based controller alone fills the path's buffer before it
//! learns anything. Nothing here reads a clock; every method takes the time.

use crate::loss::{MAX_TRACKED, Rtt, micros};
use std::time::{Duration, Instant};

/// Datagrams the window starts at, RFC 9002's initial window.
const INITIAL_DATAGRAMS: usize = 10;

/// Two, so a receiver acknowledging every second packet never waits on a timer.
const MIN_DATAGRAMS: usize = 2;

/// A lossless low-latency path gives [`Congestion::check_overshoot`] nothing to
/// fire on. In datagrams, so it is comparable with [`MAX_TRACKED`].
const MAX_DATAGRAMS: usize = 512;

const _: () = assert!(MAX_DATAGRAMS <= MAX_TRACKED);

/// Datagrams the pacer may release back to back.
const BURST_DATAGRAMS: usize = 10;

/// Slightly above the window per round trip, so a connection that is not the
/// bottleneck is not held back by its own spacing.
const PACE_NUMERATOR: u128 = 5;
const PACE_DENOMINATOR: u128 = 4;

/// How long the initial window takes to leave before a round trip is known.
const INITIAL_PACE: Duration = Duration::from_millis(100);

/// Three, from RFC 9406, because one is jitter.
const OVERSHOOT_SAMPLES: u32 = 3;

/// Slow start ends when the round trip rises by this much over its minimum.
const OVERSHOOT_FLOOR: Duration = Duration::from_millis(4);

/// A token bucket, refilled at the window's own rate.
/// [`available`](Pacer::available) is clock-pure, so "may I send" needs no
/// mutable borrow.
struct Pacer {
    tokens: usize,
    /// `None` until the first send, so a connection opens with a full bucket.
    refilled: Option<Instant>,
}

impl Pacer {
    const fn new() -> Self {
        Self {
            tokens: 0,
            refilled: None,
        }
    }

    fn available(
        &self,
        now: Instant,
        window: usize,
        burst: usize,
        srtt: Option<Duration>,
    ) -> usize {
        let Some(refilled) = self.refilled else {
            return burst;
        };
        let elapsed = u128::from(micros(now.saturating_duration_since(refilled)));
        let gained = match srtt {
            Some(srtt) => {
                let srtt = u128::from(micros(srtt)).max(1);
                elapsed * PACE_NUMERATOR * wide(window) / (PACE_DENOMINATOR * srtt)
            }
            // Unmeasured: a flight per 100 ms, a slow path's round trip.
            None => elapsed * wide(window) / u128::from(micros(INITIAL_PACE)),
        };
        let gained = usize::try_from(gained).unwrap_or(usize::MAX);
        self.tokens.saturating_add(gained).min(burst)
    }

    fn spend(
        &mut self,
        bytes: usize,
        now: Instant,
        window: usize,
        burst: usize,
        srtt: Option<Duration>,
    ) {
        self.tokens = self
            .available(now, window, burst, srtt)
            .saturating_sub(bytes);
        self.refilled = Some(now);
    }

    /// Rounded up: truncating names an instant at which it is one byte short.
    fn ready(
        &self,
        now: Instant,
        bytes: usize,
        window: usize,
        burst: usize,
        srtt: Option<Duration>,
    ) -> Instant {
        let short = bytes.saturating_sub(self.available(now, window, burst, srtt));
        if short == 0 {
            return now;
        }
        let window = wide(window.max(1));
        let wait = match srtt {
            Some(srtt) => (u128::from(micros(srtt)) * PACE_DENOMINATOR * wide(short))
                .div_ceil(PACE_NUMERATOR * window),
            None => (u128::from(micros(INITIAL_PACE)) * wide(short)).div_ceil(window),
        };
        now + Duration::from_micros(u64::try_from(wait).unwrap_or(u64::MAX))
    }
}

pub struct Congestion {
    window: usize,
    ssthresh: usize,
    in_flight: usize,
    /// How avoidance adds one datagram per round trip without knowing where one
    /// begins.
    credit: usize,
    /// The rest of the flight in the air with a loss must not halve it again.
    recovery_start: Option<Instant>,
    datagram: usize,
    /// Consecutive round-trip samples above the trigger, which ends slow start.
    overshoot: u32,
    pacer: Pacer,
    srtt: Option<Duration>,
}

impl Congestion {
    #[must_use]
    pub const fn new(datagram: usize) -> Self {
        Self {
            window: datagram * INITIAL_DATAGRAMS,
            ssthresh: usize::MAX,
            in_flight: 0,
            credit: 0,
            recovery_start: None,
            datagram,
            overshoot: 0,
            pacer: Pacer::new(),
            srtt: None,
        }
    }

    #[must_use]
    pub const fn window(&self) -> usize {
        self.window
    }

    #[must_use]
    pub const fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// The window is in bytes and stays put; only the floor and burst move.
    pub const fn datagram(&mut self, bytes: usize) {
        self.datagram = bytes;
    }

    /// The floor tracks the live path MTU, so unclamped it would let a loss
    /// *raise* the send rate after a search widened the path.
    const fn minimum(&self) -> usize {
        let floor = self.datagram * MIN_DATAGRAMS;
        if floor < self.window {
            floor
        } else {
            self.window
        }
    }

    const fn ceiling(&self) -> usize {
        self.datagram * MAX_DATAGRAMS
    }

    const fn burst(&self) -> usize {
        let burst = self.datagram * BURST_DATAGRAMS;
        if self.window < burst {
            self.window
        } else {
            burst
        }
    }

    #[must_use]
    pub fn writable(&self, now: Instant, bytes: usize) -> bool {
        self.in_flight + bytes <= self.window
            && self
                .pacer
                .available(now, self.window, self.burst(), self.srtt)
                >= bytes
    }

    /// `None` if the window is what refuses them, which only an arrival opens.
    #[must_use]
    pub fn ready(&self, now: Instant, bytes: usize) -> Option<Instant> {
        if self.in_flight + bytes > self.window {
            return None;
        }
        Some(
            self.pacer
                .ready(now, bytes, self.window, self.burst(), self.srtt),
        )
    }

    pub fn sealed(&mut self, bytes: usize, now: Instant) {
        self.in_flight += bytes;
        let (window, burst) = (self.window, self.burst());
        self.pacer.spend(bytes, now, window, burst, self.srtt);
    }

    /// One packet arrived, having been sealed at `sent`.
    pub fn acknowledged(&mut self, bytes: usize, sent: Instant, rtt: &Rtt) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
        self.srtt = rtt.smoothed();
        // The next loss is news, not an echo of the flight already in the air.
        if self.recovery_start.is_some_and(|start| sent > start) {
            self.recovery_start = None;
        }
        let ceiling = self.ceiling();
        if self.window < self.ssthresh {
            self.window = (self.window + bytes).min(ceiling);
            self.check_overshoot(rtt);
            return;
        }
        // One datagram per window acknowledged, in bytes so it needs no mark.
        self.credit += bytes;
        while self.credit >= self.window {
            self.credit -= self.window;
            self.window = (self.window + self.datagram).min(ceiling);
        }
    }

    /// One packet was lost, having been sealed at `sent`.
    pub fn lost(&mut self, bytes: usize, sent: Instant, now: Instant) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
        if self.recovery_start.is_some_and(|start| sent < start) {
            return;
        }
        self.recovery_start = Some(now);
        self.window = (self.window / 2).max(self.minimum());
        self.ssthresh = self.window;
        self.credit = 0;
        self.overshoot = 0;
    }

    /// The window does not move: halving on silence would let a path that drops
    /// acknowledgements throttle the traffic it is still delivering.
    pub fn abandoned(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }

    /// RFC 9002 persistent congestion, answered by starting again as if new.
    pub fn collapse(&mut self, now: Instant) {
        self.window = self.minimum();
        self.credit = 0;
        self.recovery_start = Some(now);
        self.overshoot = 0;
    }

    /// RFC 9002 §5.5: a 5 ms minimum makes every 100 ms sample an overshoot.
    pub fn migrated(&mut self) {
        self.window = self.datagram * INITIAL_DATAGRAMS;
        self.ssthresh = usize::MAX;
        self.credit = 0;
        self.recovery_start = None;
        self.overshoot = 0;
        self.srtt = None;
        self.pacer = Pacer::new();
    }

    /// The same news as a loss, one bottleneck buffer earlier.
    fn check_overshoot(&mut self, rtt: &Rtt) {
        let Some(minimum) = rtt.minimum() else {
            return;
        };
        let trigger = minimum + (minimum / 8).max(OVERSHOOT_FLOOR);
        if rtt.latest() <= trigger {
            self.overshoot = 0;
            return;
        }
        self.overshoot += 1;
        if self.overshoot >= OVERSHOOT_SAMPLES {
            self.ssthresh = self.window;
        }
    }
}

/// Widen for the pacer, which multiplies a window by a span of time.
fn wide(bytes: usize) -> u128 {
    u128::try_from(bytes).unwrap_or(u128::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: usize = 1200;

    fn rtt(millis: u64) -> Rtt {
        let mut rtt = Rtt::default();
        rtt.sample(Duration::from_millis(millis), Duration::ZERO);
        rtt
    }

    #[test]
    fn the_window_starts_at_ten_datagrams_and_doubles_over_a_flight() {
        let mut congestion = Congestion::new(MSS);
        let now = Instant::now();
        assert_eq!(congestion.window(), 10 * MSS);
        let rtt = rtt(50);
        for _ in 0..10 {
            congestion.acknowledged(MSS, now, &rtt);
        }
        assert_eq!(congestion.window(), 20 * MSS, "slow start doubles");
    }

    #[test]
    fn a_loss_halves_the_window_leaves_slow_start_and_stops_at_the_floor() {
        let mut congestion = Congestion::new(MSS);
        let mut now = Instant::now();
        congestion.sealed(MSS, now);
        congestion.lost(MSS, now, now);
        assert_eq!(congestion.window(), 5 * MSS);
        assert_eq!(congestion.in_flight(), 0);
        // A whole window of acks buys one datagram, not another window.
        let rtt = rtt(50);
        for _ in 0..5 {
            congestion.acknowledged(MSS, now + Duration::from_millis(100), &rtt);
        }
        assert_eq!(congestion.window(), 6 * MSS);
        // And no run of signals takes it below the floor.
        for _ in 0..20 {
            congestion.sealed(MSS, now);
            congestion.lost(MSS, now, now);
            now += Duration::from_secs(1);
        }
        assert_eq!(congestion.window(), 2 * MSS);
    }

    /// Without the recovery period a flight lost together floors the window.
    #[test]
    fn a_flight_is_one_congestion_signal_but_a_later_flight_is_another() {
        let mut congestion = Congestion::new(MSS);
        let now = Instant::now();
        for _ in 0..10 {
            congestion.sealed(MSS, now);
        }
        for _ in 0..9 {
            congestion.lost(MSS, now, now + Duration::from_millis(100));
        }
        assert_eq!(congestion.window(), 5 * MSS, "one signal, one halving");

        let later = now + Duration::from_millis(200);
        congestion.sealed(MSS, later);
        congestion.lost(MSS, later, later);
        assert_eq!(congestion.window(), 2 * MSS + MSS / 2);
    }

    /// The eleventh waits for the clock, not for an acknowledgement.
    #[test]
    fn the_pacer_spaces_a_window_over_a_round_trip() {
        let mut congestion = Congestion::new(MSS);
        let now = Instant::now();
        let rtt = rtt(100);
        congestion.acknowledged(0, now, &rtt);
        let mut sent = 0;
        while congestion.writable(now, MSS) {
            congestion.sealed(MSS, now);
            sent += 1;
        }
        assert_eq!(sent, 10, "the burst is ten datagrams, not the window");
        let ready = congestion.ready(now, MSS);
        assert_eq!(ready, None, "the window is full, and only an ack opens it");
        congestion.acknowledged(MSS, now, &rtt);
        let ready = congestion.ready(now, MSS).expect("the window has room");
        assert!(ready > now, "and the pacer holds it back");
        assert!(
            ready < now + Duration::from_millis(100),
            "but by less than a round trip"
        );
        assert!(!congestion.writable(now, MSS));
        assert!(congestion.writable(ready, MSS));
    }

    /// Or the very first screen is the burst this module exists to prevent.
    #[test]
    fn an_unmeasured_path_is_paced_at_the_initial_window_per_hundred_milliseconds() {
        let mut congestion = Congestion::new(MSS);
        let now = Instant::now();
        for _ in 0..10 {
            congestion.sealed(MSS, now);
        }
        congestion.abandoned(10 * MSS);
        assert!(!congestion.writable(now, MSS));
        assert!(congestion.writable(now + INITIAL_PACE, MSS));
    }

    /// The window stops doubling while the buffer is filling, not once full.
    #[test]
    fn a_climbing_round_trip_ends_slow_start_before_anything_is_lost() {
        let mut congestion = Congestion::new(MSS);
        let now = Instant::now();
        let mut rtt = rtt(100);
        congestion.acknowledged(MSS, now, &rtt);
        let doubling = congestion.window();
        for _ in 0..OVERSHOOT_SAMPLES {
            rtt.sample(Duration::from_millis(300), Duration::ZERO);
            congestion.acknowledged(MSS, now, &rtt);
        }
        let stopped = congestion.window();
        for _ in 0..20 {
            rtt.sample(Duration::from_millis(300), Duration::ZERO);
            congestion.acknowledged(MSS, now, &rtt);
        }
        assert!(doubling < stopped);
        assert!(
            congestion.window() < stopped + 2 * MSS,
            "congestion avoidance, not doubling"
        );
    }

    /// An unclamped floor would grow past the window when a search widens it.
    #[test]
    fn a_congestion_signal_never_raises_the_window() {
        let mut congestion = Congestion::new(MSS);
        let now = Instant::now();
        let rtt = rtt(20);
        for _ in 0..40 {
            congestion.acknowledged(MSS, now, &rtt);
        }
        assert!(congestion.window() > 10 * MSS);
        congestion.collapse(now);
        assert_eq!(
            congestion.window(),
            2 * MSS,
            "and silence takes it to the floor"
        );
        congestion.datagram(1400);
        let before = congestion.window();
        congestion.lost(0, now, now);
        assert!(congestion.window() <= before, "a loss is not an opening");
        let before = congestion.window();
        congestion.collapse(now);
        assert!(
            congestion.window() <= before,
            "neither is persistent congestion"
        );
    }

    /// A path that never drops gives the delay trigger nothing to fire on.
    #[test]
    fn a_lossless_path_saturates_the_window_rather_than_growing_for_ever() {
        let mut congestion = Congestion::new(MSS);
        let now = Instant::now();
        let rtt = rtt(1);
        for _ in 0..(MAX_DATAGRAMS * 4) {
            congestion.acknowledged(MSS, now, &rtt);
        }
        assert_eq!(congestion.window(), MAX_DATAGRAMS * MSS);
        // The ceiling does not depend on which growth path the window is on.
        congestion.lost(0, now, now);
        for _ in 0..(MAX_DATAGRAMS * 4) {
            let full = congestion.window();
            congestion.acknowledged(full, now, &rtt);
        }
        assert_eq!(congestion.window(), MAX_DATAGRAMS * MSS);
    }
}
