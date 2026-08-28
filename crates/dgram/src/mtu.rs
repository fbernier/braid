#![forbid(unsafe_code)]

//! What size datagram this path carries, found by trying: RFC 8899's search
//! over four fixed candidates. Congestion loss must never be read as a black
//! hole, so silence never narrows the path and only probes at the width in
//! force can lower it. A probe arriving in four IP fragments answers a question
//! the path answers "no" to, hence [`Fragmentation`] as the caller's premise.

use crate::packet::{BASE_DATAGRAM, MAX_DATAGRAM};
use std::time::{Duration, Instant};

/// Sizes that exist in practice: Ethernet, Ethernet under a tunnel, jumbo.
const CANDIDATES: [usize; 4] = [1400, 1500, 4000, 8900];

/// Two, because one is the ordinary loss any link produces.
const CANDIDATE_LOSSES: u8 = 2;

/// Losses above the base size before the path is *suspected* of narrowing.
pub const PMTU_BLACKHOLE_LOSSES: u32 = 3;

/// Data loss only raises the question; probes answer it.
const CONFIRM_LOSSES: u8 = 2;

/// Longer than any planned round trip, so two probes are two questions.
const PROBE_SPACING: Duration = Duration::from_secs(1);

/// A route change or a tunnel appearing does not un-happen in a second.
const COOLDOWN: Duration = Duration::from_mins(1);

/// Two lost probes are as likely one burst as a size the path refuses.
const SEARCH_RETRY: Duration = Duration::from_mins(1);

/// Whether a probe that comes back is evidence of anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fragmentation {
    /// Oversize fails at the socket, so a probe proves the path carries it.
    Refused,
    /// The kernel will cut an oversize datagram up, so a probe proves nothing.
    Permitted,
}

#[derive(Clone, Copy)]
enum Search {
    /// Nothing has proved the path carries anything yet.
    Unproven,
    Asking {
        candidate: usize,
        outstanding: Option<u64>,
        lost: u8,
        /// `None` for a candidate nothing has been asked of yet.
        due: Option<Instant>,
    },
    /// Nothing above the size in force is left, or this connection may never
    /// probe. Only [`Search::Cooling`] restarts.
    Settled,
    /// Only [`CONFIRM_LOSSES`] probes of that exact size failing lower `plpmtu`.
    Confirming {
        due: Instant,
        outstanding: Option<u64>,
        lost: u8,
    },
    /// The path stopped carrying a size it had accepted.
    Cooling { until: Instant },
}

pub struct Mtu {
    plpmtu: usize,
    search: Search,
    next: usize,
    /// Packets above the base size lost since the last one that large arrived.
    blackhole: u32,
    /// The size an arrival must reach to end the run; against `plpmtu` a path
    /// carrying 3000 bytes would read as carrying none.
    suspect: usize,
    /// Without it a path that went down looks like one that narrowed.
    small_arrived: bool,
}

impl Mtu {
    #[must_use]
    pub const fn new(fragmentation: Fragmentation) -> Self {
        Self {
            plpmtu: BASE_DATAGRAM,
            // A search whose probes prove nothing must never run: `Settled`
            // emits none, and every exit needs a probe or a loss above base.
            search: match fragmentation {
                Fragmentation::Refused => Search::Unproven,
                Fragmentation::Permitted => Search::Settled,
            },
            next: 0,
            blackhole: 0,
            suspect: usize::MAX,
            small_arrived: false,
        }
    }

    #[must_use]
    pub const fn datagram(&self) -> usize {
        self.plpmtu
    }

    /// The path has carried something and brought back proof.
    pub fn proven(&mut self) {
        if matches!(self.search, Search::Unproven) {
            self.begin();
        }
    }

    /// The caller pads to exactly this and reports the number through
    /// [`probing`](Self::probing); two outstanding sizes cannot be told apart.
    pub fn poll(&mut self, now: Instant) -> Option<usize> {
        if let Search::Cooling { until } = self.search
            && now >= until
        {
            self.begin();
        }
        match self.search {
            Search::Asking {
                candidate,
                outstanding: None,
                due,
                ..
            } if due.is_none_or(|due| now >= due) => Some(candidate),
            // Charged on being offered: a refused probe asked nothing, and
            // re-offering each tick would spin against a shut window.
            Search::Confirming {
                due,
                outstanding: None,
                lost,
            } if now >= due => {
                self.search = Search::Confirming {
                    due: now + PROBE_SPACING,
                    outstanding: None,
                    lost,
                };
                Some(self.plpmtu)
            }
            _ => None,
        }
    }

    /// A search probe is an optimisation the window may refuse; a confirmation
    /// is all that stands between a congested link and a path reduction.
    #[must_use]
    pub const fn confirming(&self) -> bool {
        matches!(self.search, Search::Confirming { .. })
    }

    pub fn probing(&mut self, number: u64) {
        match &mut self.search {
            Search::Asking { outstanding, .. } | Search::Confirming { outstanding, .. } => {
                *outstanding = Some(number);
            }
            Search::Unproven | Search::Settled | Search::Cooling { .. } => {}
        }
    }

    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        match self.search {
            Search::Cooling { until } => Some(until),
            Search::Asking {
                outstanding: None,
                due,
                ..
            } => due,
            Search::Confirming {
                due,
                outstanding: None,
                ..
            } => Some(due),
            _ => None,
        }
    }

    pub fn acknowledged(&mut self, number: u64, bytes: usize) {
        if bytes <= BASE_DATAGRAM {
            self.small_arrived = true;
        }
        let answered = match self.search {
            Search::Asking {
                candidate,
                outstanding: Some(outstanding),
                ..
            } if outstanding == number => {
                self.plpmtu = candidate.min(MAX_DATAGRAM);
                self.next += 1;
                true
            }
            // Crossed under a packet sent to ask, so the link was full, not narrow.
            Search::Confirming {
                outstanding: Some(outstanding),
                ..
            } if outstanding == number => true,
            _ => false,
        };
        if answered || bytes >= self.suspect {
            self.withdraw();
        }
        if answered {
            self.begin();
        }
    }

    /// A queue still delivering three kilobytes still carries three kilobytes.
    fn withdraw(&mut self) {
        self.blackhole = 0;
        self.suspect = usize::MAX;
        self.small_arrived = false;
        if matches!(self.search, Search::Confirming { .. }) {
            self.begin();
        }
    }

    /// The only cause that may raise the question; a lost probe answers it.
    pub fn lost(&mut self, number: u64, bytes: usize, now: Instant) {
        if self.probe_gone(number, now) {
            return;
        }
        if bytes <= BASE_DATAGRAM || self.plpmtu <= BASE_DATAGRAM {
            return;
        }
        self.blackhole += 1;
        self.suspect = self.suspect.min(bytes);
        if self.blackhole < PMTU_BLACKHOLE_LOSSES || !self.small_arrived {
            return;
        }
        if !matches!(self.search, Search::Confirming { .. }) {
            self.search = Search::Confirming {
                due: now,
                outstanding: None,
                lost: 0,
            };
        }
    }

    /// Says nothing about width: a flood times big datagrams out on loopback.
    pub fn abandoned(&mut self, number: u64, now: Instant) {
        self.probe_gone(number, now);
    }

    /// The kernel refused a datagram this wide and named what the path does
    /// carry: the one narrowing this search gets without first paying
    /// [`PMTU_BLACKHOLE_LOSSES`] losses and the probes that would confirm them.
    pub fn refused(&mut self, carries: usize, now: Instant) {
        // Never upwards. What the kernel holds is the first hop's width less
        // whatever an ICMP report has lowered it to, so it bounds the path
        // rather than proving it, and only a probe that came back proves.
        let carries = carries.clamp(BASE_DATAGRAM, MAX_DATAGRAM);
        if carries >= self.plpmtu {
            return;
        }
        self.narrowed(carries, now);
    }

    fn probe_gone(&mut self, number: u64, now: Instant) -> bool {
        match self.search {
            Search::Asking {
                candidate,
                outstanding: Some(outstanding),
                lost,
                ..
            } if outstanding == number => {
                // Every size above is larger, so nothing is left to ask until
                // the path has had time to become a different one.
                self.search = if lost + 1 >= CANDIDATE_LOSSES {
                    Search::Cooling {
                        until: now + SEARCH_RETRY,
                    }
                } else {
                    Search::Asking {
                        candidate,
                        outstanding: None,
                        lost: lost + 1,
                        due: Some(now + PROBE_SPACING),
                    }
                };
                true
            }
            Search::Confirming {
                outstanding: Some(outstanding),
                lost,
                ..
            } if outstanding == number => {
                self.confirmed_lost(lost + 1, now);
                true
            }
            _ => false,
        }
    }

    fn confirmed_lost(&mut self, lost: u8, now: Instant) {
        if lost < CONFIRM_LOSSES {
            self.search = Search::Confirming {
                due: now + PROBE_SPACING,
                outstanding: None,
                lost,
            };
            return;
        }
        if !self.small_arrived {
            // Nothing gets through at any size: a stopped path, not a narrow one.
            self.withdraw();
            return;
        }
        self.narrowed(BASE_DATAGRAM, now);
    }

    /// Drop to a width and stop asking for a while: what a path that narrowed
    /// under a working connection costs, whichever way this side found out.
    fn narrowed(&mut self, carries: usize, now: Instant) {
        self.plpmtu = carries;
        self.blackhole = 0;
        self.suspect = usize::MAX;
        self.small_arrived = false;
        // The path that carried 1500 a minute ago is not this path.
        self.next = 0;
        self.search = Search::Cooling {
            until: now + COOLDOWN,
        };
    }

    fn begin(&mut self) {
        while let Some(&candidate) = CANDIDATES.get(self.next) {
            // A candidate at or below the size in force says nothing.
            if candidate > self.plpmtu {
                self.search = Search::Asking {
                    candidate,
                    outstanding: None,
                    lost: 0,
                    due: None,
                };
                return;
            }
            self.next += 1;
        }
        self.search = Search::Settled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probed(mtu: &mut Mtu, now: Instant, number: u64) -> usize {
        let size = mtu.poll(now).expect("a probe is due");
        mtu.probing(number);
        size
    }

    /// A fresh search taken to the first candidate the path accepted.
    fn at_1400(now: Instant) -> Mtu {
        let mut mtu = Mtu::new(Fragmentation::Refused);
        mtu.proven();
        assert_eq!(probed(&mut mtu, now, 1), 1400);
        mtu.acknowledged(1, 1400);
        assert_eq!(mtu.datagram(), 1400);
        mtu
    }

    /// A fresh search walked up to the largest candidate, checking the order.
    fn grown(now: Instant) -> Mtu {
        let mut mtu = Mtu::new(Fragmentation::Refused);
        mtu.proven();
        for (number, size) in [(1, 1400), (2, 1500), (3, 4000), (4, 8900)] {
            assert_eq!(probed(&mut mtu, now, number), size);
            mtu.acknowledged(number, size);
            assert_eq!(mtu.datagram(), size);
        }
        mtu
    }

    /// Three losses above the size in force with something small still
    /// arriving: the run that raises the question a probe then answers.
    fn suspected(mtu: &mut Mtu, bytes: usize, now: Instant) {
        mtu.acknowledged(10, 200);
        for number in 20..23 {
            mtu.lost(number, bytes, now);
        }
    }

    #[test]
    fn nothing_is_probed_until_the_path_has_proved_itself() {
        let mut mtu = Mtu::new(Fragmentation::Refused);
        let now = Instant::now();
        assert_eq!(mtu.poll(now), None);
        assert_eq!(mtu.datagram(), BASE_DATAGRAM);
        mtu.proven();
        assert_eq!(mtu.poll(now), Some(1400));
    }

    #[test]
    fn a_probe_that_arrives_raises_the_size_and_asks_for_more() {
        let now = Instant::now();
        let mut mtu = grown(now);
        assert_eq!(mtu.datagram(), 8900);
        assert_eq!(mtu.poll(now), None, "nothing left to ask");
    }

    /// Two is a size the path refuses today; the retry is spaced so the two
    /// probes are two questions.
    #[test]
    fn a_candidate_lost_twice_ends_the_search_at_the_size_that_worked() {
        let mut now = Instant::now();
        let mut mtu = at_1400(now);
        assert_eq!(probed(&mut mtu, now, 2), 1500);
        mtu.lost(2, 1500, now);
        assert_eq!(mtu.poll(now), None, "not into the same queue");
        assert_eq!(mtu.deadline(), Some(now + PROBE_SPACING));
        now += PROBE_SPACING;
        assert_eq!(probed(&mut mtu, now, 3), 1500, "one more chance");
        mtu.lost(3, 1500, now);
        assert_eq!(mtu.poll(now), None);
        assert_eq!(mtu.datagram(), 1400);
    }

    /// A cooldown, not for good: one burst must not cost a session its width.
    #[test]
    fn a_candidate_that_lost_every_probe_is_asked_again_after_a_cooldown() {
        let mut mtu = Mtu::new(Fragmentation::Refused);
        let mut now = Instant::now();
        mtu.proven();
        let mut last = now;
        for number in 1..=CANDIDATE_LOSSES {
            assert_eq!(probed(&mut mtu, now, u64::from(number)), 1400);
            mtu.lost(u64::from(number), 1400, now);
            last = now;
            now += PROBE_SPACING;
        }
        assert_eq!(mtu.poll(now), None, "the burst is not asked through");
        assert_eq!(mtu.datagram(), BASE_DATAGRAM);

        let until = last + SEARCH_RETRY;
        assert_eq!(mtu.deadline(), Some(until));
        assert_eq!(mtu.poll(until), Some(1400), "and the search comes back");
    }

    /// The path stops carrying the size it accepted, small packets get
    /// through, and the session shows nothing while looking healthy.
    #[test]
    fn a_path_that_stops_carrying_full_size_packets_falls_back_to_the_base() {
        let mut now = Instant::now();
        let mut mtu = at_1400(now);
        suspected(&mut mtu, 1400, now);
        assert_eq!(mtu.datagram(), 1400, "a question, not an answer");

        for number in 30..32 {
            assert_eq!(mtu.poll(now), Some(1400), "asked at the size in force");
            mtu.probing(number);
            mtu.lost(number, 1400, now);
            if number == 30 {
                now += PROBE_SPACING;
            }
        }
        assert_eq!(mtu.datagram(), BASE_DATAGRAM, "both probes gone");
        assert_eq!(mtu.poll(now), None, "and it is left alone for a while");

        now += COOLDOWN;
        assert_eq!(mtu.deadline(), Some(now));
        assert_eq!(mtu.poll(now), Some(1400), "then the search restarts");
    }

    /// A flood on loopback outruns the peer's acks, so `lost` stays at zero.
    #[test]
    fn packets_nobody_ever_mentioned_are_silence_rather_than_a_narrow_path() {
        let now = Instant::now();
        let mut mtu = grown(now);
        for number in 20..60 {
            mtu.abandoned(number, now);
            mtu.acknowledged(number + 100, 120);
        }
        assert_eq!(mtu.datagram(), 8900, "silence is not evidence of width");
        assert_eq!(mtu.deadline(), None, "and nothing is being confirmed");
    }

    /// A link that went down entirely is not a black hole.
    #[test]
    fn losses_with_nothing_at_all_arriving_do_not_look_like_a_black_hole() {
        let now = Instant::now();
        let mut mtu = at_1400(now);
        for number in 20..40 {
            mtu.lost(number, 1400, now);
        }
        assert_eq!(mtu.datagram(), 1400);
    }

    /// A full-size packet mid-run says the path is fine and merely lossy.
    #[test]
    fn a_full_size_packet_arriving_clears_the_run_of_losses() {
        let now = Instant::now();
        let mut mtu = at_1400(now);
        mtu.acknowledged(10, 200);
        mtu.lost(20, 1400, now);
        mtu.lost(21, 1400, now);
        mtu.acknowledged(22, 1400);
        mtu.lost(23, 1400, now);
        mtu.lost(24, 1400, now);
        assert_eq!(mtu.datagram(), 1400, "the count started again");
        assert_eq!(mtu.poll(now), Some(1500), "and the search never paused");
    }

    /// The packets flying are two and three kilobytes, so against `plpmtu`
    /// none of them could ever clear the run.
    #[test]
    fn an_arrival_below_the_size_in_force_clears_a_run_of_losses_of_its_own_size() {
        let now = Instant::now();
        let mut mtu = grown(now);
        mtu.acknowledged(10, 200);
        for number in 20..40 {
            mtu.lost(number, 3000, now);
            mtu.acknowledged(number + 100, 3000);
        }
        assert_eq!(mtu.datagram(), 8900, "still delivering three kilobytes");
        assert_eq!(mtu.deadline(), None, "and nothing is being confirmed");
    }

    /// The largest thing sent, so a merely full queue drops it first.
    #[test]
    fn traffic_of_the_suspected_size_withdraws_a_confirmation_in_flight() {
        let mut now = Instant::now();
        let mut mtu = grown(now);
        suspected(&mut mtu, 3000, now);
        assert_eq!(probed(&mut mtu, now, 30), 8900, "the question is asked");
        mtu.lost(30, 8900, now);
        now += PROBE_SPACING;

        mtu.acknowledged(31, 3000);
        assert_eq!(mtu.deadline(), None, "the arrival answered it");
        mtu.lost(32, 8900, now);
        mtu.lost(33, 8900, now);
        assert_eq!(mtu.datagram(), 8900, "no probe is owed now");
    }

    /// The probe gets through, so the run was a full queue.
    #[test]
    fn a_confirmation_probe_that_arrives_withdraws_the_question() {
        let now = Instant::now();
        let mut mtu = at_1400(now);
        suspected(&mut mtu, 1400, now);
        assert_eq!(probed(&mut mtu, now, 30), 1400);
        mtu.acknowledged(30, 1400);
        assert_eq!(mtu.datagram(), 1400);
        assert_eq!(mtu.poll(now), Some(1500), "the search picks up again");

        for number in 40..43 {
            mtu.lost(number, 1400, now);
        }
        assert_eq!(mtu.datagram(), 1400, "a fresh run is a fresh question");
    }

    /// Charged when offered, so a shut window cannot make this a spin.
    #[test]
    fn confirmation_probes_are_spaced_so_no_two_land_in_one_congestion_event() {
        let mut now = Instant::now();
        let mut mtu = at_1400(now);
        suspected(&mut mtu, 1400, now);
        assert_eq!(probed(&mut mtu, now, 30), 1400);
        mtu.lost(30, 1400, now);
        assert_eq!(mtu.deadline(), Some(now + PROBE_SPACING));
        assert_eq!(mtu.poll(now), None, "not yet");
        now += PROBE_SPACING;
        assert_eq!(mtu.poll(now), Some(1400));
        assert_eq!(mtu.poll(now), None, "an untaken offer still costs");
    }

    /// The kernel's own answer to a datagram it would not send, which costs
    /// neither a run of losses nor the probes that would confirm one.
    #[test]
    fn a_refusal_that_names_the_width_narrows_the_path_at_once() {
        let mut now = Instant::now();
        let mut mtu = grown(now);
        mtu.refused(1500, now);
        assert_eq!(mtu.datagram(), 1500, "no loss was needed");
        assert_eq!(mtu.poll(now), None, "and the path is then left alone");

        now += COOLDOWN;
        assert_eq!(mtu.deadline(), Some(now));
        assert_eq!(
            mtu.poll(now),
            Some(4000),
            "the search comes back above the width it was given"
        );
    }

    /// A refusal naming the size in force or more is a probe being refused,
    /// and a route's width bounds the path rather than proving it.
    #[test]
    fn a_refusal_never_widens_the_path_and_never_goes_under_the_base() {
        let now = Instant::now();
        let mut mtu = at_1400(now);
        mtu.refused(4000, now);
        assert_eq!(mtu.datagram(), 1400);
        assert_eq!(mtu.poll(now), Some(1500), "the search is untouched");

        mtu.refused(576, now);
        assert_eq!(mtu.datagram(), BASE_DATAGRAM, "the floor holds");
    }

    /// Every probe is a lie the search cannot catch, so it never starts.
    #[test]
    fn a_socket_that_fragments_never_searches_at_all() {
        let mut mtu = Mtu::new(Fragmentation::Permitted);
        let mut now = Instant::now();
        assert_eq!(mtu.poll(now), None);
        mtu.proven();
        assert_eq!(mtu.poll(now), None, "the first proof starts nothing");
        assert_eq!(mtu.deadline(), None);

        // Every event the search reads, in the order it would have walked.
        for (number, size) in [(1, 1400), (2, 1500), (3, 4000), (4, 8900)] {
            mtu.probing(number);
            mtu.acknowledged(number, size);
            assert_eq!(mtu.poll(now), None);
        }
        mtu.acknowledged(10, 200);
        for number in 20..40 {
            mtu.lost(number, 8900, now);
            mtu.abandoned(number + 100, now);
        }
        now += COOLDOWN + PROBE_SPACING;
        assert_eq!(mtu.poll(now), None, "and no timer brings it back");
        assert_eq!(mtu.deadline(), None);
        assert!(!mtu.confirming());
        assert_eq!(mtu.datagram(), BASE_DATAGRAM);
    }
}
