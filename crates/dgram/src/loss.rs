#![forbid(unsafe_code)]

//! What is in flight, how long the round trip is, and what did not arrive.
//! Nothing here retransmits: loss feeds the congestion controller and the MTU
//! search only. A packet the peer acknowledged *around* is congestion; one
//! nothing was said about is dropped after a probe timeout without shrinking
//! the window, and only sustained silence does that.

use crate::packet::Ack;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// RFC 9002's packet threshold: three is more reordering than a working path.
const PACKET_THRESHOLD: u64 = 3;

/// RFC 9002's initial value; only the first flight is ever timed against it.
const INITIAL_RTT: Duration = Duration::from_millis(333);

/// So a link measured in microseconds does not declare loss on scheduler jitter.
const MIN_LOSS_DELAY: Duration = Duration::from_millis(1);

/// The peer adds this to its probe timeout, so a delayed ack is not a loss.
pub const MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// So a peer that acknowledges nothing cannot grow this side's memory. The
/// oldest are abandoned, not lost.
pub(crate) const MAX_TRACKED: usize = 4096;

/// Two, because one timeout is a burst.
pub(crate) const PERSISTENT_SILENCE: u32 = 2;

/// RFC 9002 §6.2.1, bounded or an hour of backoff costs an hour of recovery.
const MAX_PTO_BACKOFF: u32 = 6;

/// Jacobson, in microseconds: `Duration`'s arithmetic is float or `u128`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rtt {
    smoothed: Option<u64>,
    var: u64,
    latest: u64,
    min: Option<u64>,
}

impl Rtt {
    /// `delay` is what the peer admits to holding it, and comes off the top.
    pub fn sample(&mut self, taken: Duration, delay: Duration) {
        let taken = micros(taken);
        self.latest = taken;
        self.min = Some(self.min.map_or(taken, |min| min.min(taken)));
        // Never to zero, or a peer claiming a negative trip pins the loss delay.
        let adjusted = taken.saturating_sub(micros(delay)).max(1);
        let Some(smoothed) = self.smoothed else {
            self.smoothed = Some(adjusted);
            self.var = adjusted / 2;
            return;
        };
        let difference = smoothed.abs_diff(adjusted);
        self.var = (self.var * 3 + difference) / 4;
        self.smoothed = Some((smoothed * 7 + adjusted) / 8);
    }

    #[must_use]
    pub fn smoothed(&self) -> Option<Duration> {
        self.smoothed.map(Duration::from_micros)
    }

    #[must_use]
    pub const fn variation(&self) -> Duration {
        Duration::from_micros(self.var)
    }

    #[must_use]
    pub const fn latest(&self) -> Duration {
        Duration::from_micros(self.latest)
    }

    /// The closest thing to the path's propagation delay with no queue in it.
    #[must_use]
    pub fn minimum(&self) -> Option<Duration> {
        self.min.map(Duration::from_micros)
    }

    /// How long a packet may go unacknowledged, with later ones acknowledged.
    #[must_use]
    pub fn loss_delay(&self) -> Duration {
        let base = self
            .smoothed
            .map_or(micros(INITIAL_RTT), |smoothed| smoothed.max(self.var));
        Duration::from_micros(base * 9 / 8).max(MIN_LOSS_DELAY)
    }

    /// Before backoff; [`LossDetector::probe_timeout`] is what a sender waits.
    #[must_use]
    pub fn probe_timeout(&self) -> Duration {
        let smoothed = self.smoothed.unwrap_or(micros(INITIAL_RTT));
        Duration::from_micros(smoothed + 4 * self.var) + MAX_ACK_DELAY
    }
}

/// No epoch: numbers ascend for the connection's life, so one names one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InFlight {
    pub number: u64,
    pub bytes: usize,
    pub sent: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrived {
    pub number: u64,
    pub bytes: usize,
    pub sent: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The peer acknowledged packets around it. Evidence of congestion.
    Lost,
    /// Nothing was ever said about it. Evidence of nothing, until it repeats.
    Abandoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gone {
    pub number: u64,
    pub bytes: usize,
    pub sent: Instant,
    pub cause: Cause,
}

/// Names only packets this side has sealed: `largest` is a high-water mark
/// never lowered, so one naming a packet nobody sealed writes off the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acknowledgement(Ack);

impl Acknowledgement {
    /// `next` is the number this side will seal next.
    #[must_use]
    pub const fn checked(ack: Ack, next: u64) -> Option<Self> {
        if ack.largest < next {
            Some(Self(ack))
        } else {
            None
        }
    }
}

pub struct LossDetector {
    sent: VecDeque<InFlight>,
    rtt: Rtt,
    largest_acked: Option<u64>,
    /// Read by the caller before the next call, so an ack costs no allocation.
    arrived: Vec<Arrived>,
    gone: Vec<Gone>,
    /// So a late acknowledgement is counted as the mistake it proves.
    written_off: VecDeque<u64>,
    silence: u32,
    persistent: bool,
    losses: u64,
    spurious: u64,
}

impl Default for LossDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LossDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sent: VecDeque::new(),
            rtt: Rtt {
                smoothed: None,
                var: 0,
                latest: 0,
                min: None,
            },
            largest_acked: None,
            arrived: Vec::new(),
            gone: Vec::new(),
            written_off: VecDeque::new(),
            silence: 0,
            persistent: false,
            losses: 0,
            spurious: 0,
        }
    }

    #[must_use]
    pub const fn rtt(&self) -> &Rtt {
        &self.rtt
    }

    /// Packets acknowledged by the last call, oldest first.
    #[must_use]
    pub fn arrived(&self) -> &[Arrived] {
        &self.arrived
    }

    /// Packets the last call gave up on, oldest first.
    #[must_use]
    pub fn gone(&self) -> &[Gone] {
        &self.gone
    }

    #[must_use]
    pub const fn silence(&self) -> u32 {
        self.silence
    }

    /// True once per run: a run is one congestion event.
    #[must_use]
    pub const fn persistent_congestion(&self) -> bool {
        self.persistent
    }

    /// Doubled per consecutive timeout, reset by anything the peer says.
    #[must_use]
    pub fn probe_timeout(&self) -> Duration {
        self.rtt
            .probe_timeout()
            .saturating_mul(1u32 << self.silence.min(MAX_PTO_BACKOFF))
    }

    /// Nothing measured on the old path is evidence about this one (RFC 9002 §5.5).
    pub fn migrated(&mut self) {
        self.rtt = Rtt::default();
        self.silence = 0;
    }

    #[must_use]
    pub const fn losses(&self) -> u64 {
        self.losses
    }

    /// Which is what says the detector is too impatient for this path.
    #[must_use]
    pub const fn spurious(&self) -> u64 {
        self.spurious
    }

    #[must_use]
    pub fn tracked(&self) -> usize {
        self.sent.len()
    }

    /// A packet the table cannot hold is one nothing would be said about, so
    /// admission refuses rather than the table going blind.
    #[must_use]
    pub fn admits(&self) -> bool {
        self.sent.len() < MAX_TRACKED
    }

    pub fn sealed(&mut self, packet: InFlight) {
        self.clear();
        self.sent.push_back(packet);
        while self.sent.len() > MAX_TRACKED
            && let Some(oldest) = self.sent.pop_front()
        {
            self.retire(oldest, Cause::Abandoned);
        }
    }

    /// Only from the newest packet named, and only the first time: a repeat
    /// measures the peer's patience rather than the path.
    pub fn acknowledged(&mut self, ack: Acknowledgement, now: Instant) -> Option<Duration> {
        let ack = &ack.0;
        self.clear();
        self.silence = 0;
        self.largest_acked = Some(
            self.largest_acked
                .map_or(ack.largest, |seen| seen.max(ack.largest)),
        );
        let mut sample = None;
        // Backwards: [`covers`] only names `largest - 64 ..= largest` and the
        // flight ascends, so the scan stops early and pops off the end.
        let mut index = self.sent.len();
        while index > 0 {
            index -= 1;
            let packet = self.sent[index];
            if packet.number + 64 < ack.largest {
                break;
            }
            if !covers(ack, packet.number) {
                continue;
            }
            self.sent.remove(index);
            if packet.number == ack.largest {
                sample = Some(now.saturating_duration_since(packet.sent));
            }
            self.arrived.push(Arrived {
                number: packet.number,
                bytes: packet.bytes,
                sent: packet.sent,
            });
        }
        // The MTU search reads this in packet order to decide a black hole.
        self.arrived.reverse();
        self.count_spurious(ack);
        if let Some(taken) = sample {
            self.rtt.sample(taken, ack.delay);
        }
        self.detect(now);
        sample
    }

    /// Separate, because a silent path produces no acknowledgements.
    pub fn expire(&mut self, now: Instant) {
        self.clear();
        self.detect(now);
    }

    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        let oldest = self.sent.front()?;
        let mut deadline = oldest.sent + self.probe_timeout();
        if self
            .largest_acked
            .is_some_and(|largest| oldest.number < largest)
        {
            deadline = deadline.min(oldest.sent + self.rtt.loss_delay());
        }
        Some(deadline)
    }

    fn detect(&mut self, now: Instant) {
        let loss_delay = self.rtt.loss_delay();
        let probe_timeout = self.probe_timeout();
        let mut abandoned = false;
        // Both tests are monotone in the number, so the doomed are a prefix.
        while let Some(&oldest) = self.sent.front() {
            let age = now.saturating_duration_since(oldest.sent);
            let overtaken = self
                .largest_acked
                .is_some_and(|largest| oldest.number + PACKET_THRESHOLD <= largest);
            let stale = self
                .largest_acked
                .is_some_and(|largest| oldest.number < largest)
                && age >= loss_delay;
            let cause = if overtaken || stale {
                Cause::Lost
            } else if age >= probe_timeout {
                abandoned = true;
                Cause::Abandoned
            } else {
                break;
            };
            self.sent.pop_front();
            self.retire(oldest, cause);
        }
        if abandoned {
            self.silence += 1;
            self.persistent = self.silence == PERSISTENT_SILENCE;
        }
    }

    fn retire(&mut self, packet: InFlight, cause: Cause) {
        if cause == Cause::Lost {
            self.losses += 1;
        }
        self.written_off.push_back(packet.number);
        while self.written_off.len() > 64 {
            self.written_off.pop_front();
        }
        self.gone.push(Gone {
            number: packet.number,
            bytes: packet.bytes,
            sent: packet.sent,
            cause,
        });
    }

    fn count_spurious(&mut self, ack: &Ack) {
        let floor = ack.largest.saturating_sub(64);
        while self
            .written_off
            .front()
            .is_some_and(|&number| number < floor)
        {
            self.written_off.pop_front();
        }
        let mut index = 0;
        while index < self.written_off.len() {
            if covers(ack, self.written_off[index]) {
                self.written_off.remove(index);
                self.spurious += 1;
            } else {
                index += 1;
            }
        }
    }

    fn clear(&mut self) {
        self.arrived.clear();
        self.gone.clear();
        self.persistent = false;
    }
}

const fn covers(ack: &Ack, number: u64) -> bool {
    if number == ack.largest {
        return true;
    }
    let Some(behind) = ack.largest.checked_sub(number) else {
        return false;
    };
    behind <= 64 && ack.map & (1u64 << (behind - 1)) != 0
}

/// Saturating; every estimator here is integer arithmetic on this.
pub(crate) fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flight(number: u64, sent: Instant) -> InFlight {
        InFlight {
            number,
            bytes: 1200,
            sent,
        }
    }

    fn ack(largest: u64, map: u64) -> Acknowledgement {
        checked(Ack {
            largest,
            delay: Duration::ZERO,
            map,
        })
    }

    fn checked(ack: Ack) -> Acknowledgement {
        Acknowledgement::checked(ack, ack.largest + 1).expect("names a packet this side sealed")
    }

    #[test]
    fn a_round_trip_is_sampled_with_the_peers_own_delay_taken_off() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        detector.sealed(flight(0, now));
        let taken = detector.acknowledged(
            checked(Ack {
                largest: 0,
                delay: Duration::from_millis(20),
                map: 0,
            }),
            now + Duration::from_millis(120),
        );
        assert_eq!(taken, Some(Duration::from_millis(120)));
        assert_eq!(
            detector.rtt().smoothed(),
            Some(Duration::from_millis(100)),
            "the first sample seeds the estimator, minus the delay it admits"
        );
    }

    /// A delay is not trusted past claiming the packet came back before it left.
    #[test]
    fn an_acknowledgement_delay_longer_than_the_trip_does_not_produce_nothing() {
        let mut rtt = Rtt::default();
        rtt.sample(Duration::from_millis(10), Duration::from_secs(9));
        assert_eq!(rtt.smoothed(), Some(Duration::from_micros(1)));
    }

    /// Otherwise the "sample" measures how long the peer waited to repeat.
    #[test]
    fn a_repeated_acknowledgement_of_an_old_packet_is_not_a_sample() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        detector.sealed(flight(0, now));
        detector.sealed(flight(1, now));
        assert!(detector.acknowledged(ack(1, 0b1), now).is_some());
        assert_eq!(detector.acknowledged(ack(1, 0b1), now), None);
        assert!(detector.arrived().is_empty());
    }

    /// Both triggers: the packet threshold, and the clock one behind the newest.
    #[test]
    fn a_packet_the_peer_acknowledged_around_is_lost() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        for number in 0..4 {
            detector.sealed(flight(number, now));
        }
        detector.acknowledged(ack(3, 0b011), now);
        let gone = detector.gone();
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].number, 0);
        assert_eq!(gone[0].cause, Cause::Lost);
        assert_eq!(detector.losses(), 1);

        let mut detector = LossDetector::new();
        detector.sealed(flight(0, now));
        detector.sealed(flight(1, now + Duration::from_millis(1)));
        detector.acknowledged(ack(1, 0), now + Duration::from_millis(50));
        assert!(detector.gone().is_empty(), "a round trip and a bit");
        detector.expire(now + Duration::from_secs(2));
        assert_eq!(detector.gone().len(), 1);
        assert_eq!(detector.gone()[0].cause, Cause::Lost);
    }

    /// Without a timeout the flight never empties and the sender never sends.
    #[test]
    fn a_flight_nobody_ever_mentions_is_abandoned_rather_than_declared_lost() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        for number in 0..10 {
            detector.sealed(flight(number, now));
        }
        detector.expire(now + Duration::from_millis(100));
        assert!(detector.gone().is_empty());
        detector.expire(now + Duration::from_secs(3));
        assert_eq!(detector.gone().len(), 10);
        assert!(detector.gone().iter().all(|g| g.cause == Cause::Abandoned));
        assert_eq!(detector.losses(), 0, "silence is not congestion");
        assert_eq!(detector.silence(), 1);
        assert_eq!(detector.tracked(), 0);
    }

    #[test]
    fn a_packet_acknowledged_after_it_was_given_up_on_is_counted_as_spurious() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        for number in 0..5 {
            detector.sealed(flight(number, now));
        }
        detector.acknowledged(ack(4, 0b0111), now);
        assert_eq!(detector.gone().len(), 1, "number zero");
        assert_eq!(detector.spurious(), 0);
        detector.sealed(flight(5, now));
        detector.acknowledged(ack(5, 0b11111), now + Duration::from_millis(1));
        assert_eq!(detector.spurious(), 1);
    }

    #[test]
    fn the_deadline_is_the_reordering_delay_once_something_newer_has_arrived() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        detector.sealed(flight(0, now));
        detector.sealed(flight(1, now));
        assert_eq!(
            detector.deadline(),
            Some(now + detector.rtt().probe_timeout()),
            "nothing has arrived, so only silence can retire it"
        );
        detector.acknowledged(ack(1, 0), now + Duration::from_millis(10));
        assert_eq!(detector.deadline(), Some(now + detector.rtt().loss_delay()));
    }

    #[test]
    fn an_acknowledgement_covers_the_numbers_its_map_names_and_no_others() {
        let ack = ack(100, 0b1010);
        let ack = &ack.0;
        for (number, expected) in [
            (100, true),
            (98, true),
            (96, true),
            (99, false),
            (97, false),
            (101, false),
            (35, false),
        ] {
            assert_eq!(covers(ack, number), expected, "{number}");
        }
    }

    /// The scan stops at the first packet out of the map's reach.
    #[test]
    fn a_large_flight_gives_up_only_the_packets_an_acknowledgement_names() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        for number in 0..2000 {
            detector.sealed(flight(number, now));
        }
        // The newest, the one 64 behind it, and nothing in between or below.
        detector.acknowledged(ack(1500, 1 << 63), now);
        let arrived: Vec<u64> = detector.arrived().iter().map(|a| a.number).collect();
        assert_eq!(arrived, vec![1436, 1500]);
        assert_eq!(detector.tracked(), 2000 - 2 - detector.gone().len());
        assert!(
            !detector.gone().iter().any(|gone| gone.number > 1500),
            "nothing newer than the acknowledgement is given up on"
        );
    }

    /// One such ack makes every packet sealed afterwards overtaken, for ever.
    #[test]
    fn an_acknowledgement_beyond_what_this_side_sealed_does_not_parse() {
        let ack = Ack {
            largest: (1 << 48) - 1,
            delay: Duration::ZERO,
            map: u64::MAX,
        };
        assert_eq!(Acknowledgement::checked(ack, 4), None);
        assert!(Acknowledgement::checked(ack, 1 << 48).is_some());
        // `next` names the packet this side will seal, not one it has sealed.
        assert_eq!(Acknowledgement::checked(Ack { largest: 4, ..ack }, 4), None);
    }

    /// RFC 9002 §6.2.1: else a dead path is asked about at the same rate.
    #[test]
    fn the_probe_timeout_doubles_on_every_silent_timeout_and_an_ack_resets_it() {
        let mut detector = LossDetector::new();
        let mut now = Instant::now();
        let base = detector.probe_timeout();
        detector.sealed(flight(0, now));
        for silence in 1..=3u32 {
            now += detector.probe_timeout();
            detector.expire(now);
            assert_eq!(detector.silence(), silence);
            assert_eq!(detector.probe_timeout(), base * (1 << silence));
            detector.sealed(flight(u64::from(silence), now));
        }
        detector.acknowledged(ack(3, 0), now);
        assert_eq!(detector.probe_timeout(), detector.rtt().probe_timeout());
        assert_eq!(detector.silence(), 0);
    }

    /// Else the window pins at its floor on a path that loses acks, not data.
    #[test]
    fn persistent_congestion_is_declared_once_per_run_of_silence() {
        let mut detector = LossDetector::new();
        let mut now = Instant::now();
        detector.sealed(flight(0, now));
        now += detector.probe_timeout();
        detector.expire(now);
        assert!(!detector.persistent_congestion(), "one timeout is a burst");

        detector.sealed(flight(1, now));
        now += detector.probe_timeout();
        detector.expire(now);
        assert!(detector.persistent_congestion());

        detector.sealed(flight(2, now));
        now += detector.probe_timeout();
        detector.expire(now);
        assert!(!detector.persistent_congestion(), "already answered");

        detector.sealed(flight(3, now));
        detector.acknowledged(ack(3, 0), now);
        for number in 4..6 {
            detector.sealed(flight(number, now));
            now += detector.probe_timeout();
            detector.expire(now);
        }
        assert!(detector.persistent_congestion(), "a fresh event");
    }

    /// The byte ceiling admits twenty thousand keystroke-sized datagrams.
    #[test]
    fn the_flight_table_refuses_admission_before_it_overflows() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        for number in 0..MAX_TRACKED as u64 {
            assert!(detector.admits(), "packet {number}");
            detector.sealed(flight(number, now));
        }
        assert!(!detector.admits());
        assert_eq!(detector.gone(), [], "and nothing was abandoned to fit");
        // A caller that sealed anyway abandons its oldest rather than growing.
        for number in 0..100 {
            detector.sealed(flight(MAX_TRACKED as u64 + number, now));
        }
        assert_eq!(detector.tracked(), MAX_TRACKED);
    }

    #[test]
    fn a_migration_forgets_what_the_old_path_measured() {
        let mut detector = LossDetector::new();
        let now = Instant::now();
        detector.sealed(flight(0, now));
        detector.acknowledged(ack(0, 0), now + Duration::from_millis(5));
        assert_eq!(detector.rtt().minimum(), Some(Duration::from_millis(5)));
        detector.migrated();
        assert_eq!(detector.rtt().minimum(), None);
        assert_eq!(detector.rtt().smoothed(), None);
        assert_eq!(detector.silence(), 0);
    }
}
