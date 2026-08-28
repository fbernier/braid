#![forbid(unsafe_code)]

//! Which address this endpoint sends to, and what has to happen before it
//! changes. "The peer moved" is indistinguishable on arrival from a replayed
//! recording: the replay window refuses the recording, and path validation
//! refuses to *commit* the move until the new address answers an unguessable
//! token, sending it no more than [`AMPLIFICATION_LIMIT`] times what it sent.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Bytes this side may send to an unvalidated address per byte received.
pub const AMPLIFICATION_LIMIT: u64 = 3;

/// How long a challenge goes unanswered before it is sent again.
const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// Challenges an address gets in a row without answering: a bound on
/// *silence*, renewed while nothing contradicts the address, because four
/// chances stranded a genuinely moved client on a bursty link.
const PROBE_LIMIT: u8 = 4;

#[derive(Clone, Copy)]
struct Probe {
    /// Minted on the first challenge sent, not on arrival, or a dry entropy
    /// pool rejects a keystroke mid-move. One token for the address's life.
    token: Option<[u8; 8]>,
    /// `None` while nothing has arrived from the address to pay for one.
    due: Option<Instant>,
    sent: u8,
    /// Bytes this side may still send to the address.
    credit: u64,
}

impl Probe {
    const fn new() -> Self {
        Self {
            token: None,
            due: None,
            sent: 0,
            credit: 0,
        }
    }

    /// Credit only: the chance count is earned separately.
    fn earned(&mut self, bytes: usize) {
        let earned = AMPLIFICATION_LIMIT.saturating_mul(bytes as u64);
        self.credit = self.credit.saturating_add(earned);
    }

    fn arrived(&mut self, bytes: usize, now: Instant) {
        self.earned(bytes);
        self.sent = 0;
        self.due.get_or_insert(now);
    }

    const fn challengeable(&self) -> bool {
        self.due.is_some() && self.sent < PROBE_LIMIT
    }

    const fn deadline(&self) -> Option<Instant> {
        if self.sent < PROBE_LIMIT {
            self.due
        } else {
            None
        }
    }

    fn challenge(&mut self, now: Instant) -> Option<[u8; 8]> {
        let due = self.deadline()?;
        if now < due {
            return None;
        }
        let token = if let Some(token) = self.token {
            token
        } else {
            let mut fresh = [0u8; 8];
            let Ok(()) = getrandom::fill(&mut fresh) else {
                // A whole interval, not the next poll, or this would spin.
                self.due = Some(now + PROBE_INTERVAL);
                return None;
            };
            *self.token.insert(fresh)
        };
        self.sent += 1;
        self.due = Some(now + PROBE_INTERVAL);
        Some(token)
    }
}

enum Candidate {
    /// Nothing contradicts the move, so its own datagrams renew its chances.
    Proposed(Probe),
    /// Traffic since arrived on the address in use; renewed by nothing.
    Retiring(Probe),
}

impl Candidate {
    const fn probe(&self) -> &Probe {
        match self {
            Self::Proposed(probe) | Self::Retiring(probe) => probe,
        }
    }

    const fn probe_mut(&mut self) -> &mut Probe {
        match self {
            Self::Proposed(probe) | Self::Retiring(probe) => probe,
        }
    }

    fn arrived(&mut self, bytes: usize, now: Instant) {
        match self {
            Self::Proposed(probe) => probe.arrived(bytes, now),
            // Credit only: bought-back chances never retire a candidate.
            Self::Retiring(probe) => probe.earned(bytes),
        }
    }

    /// Traffic arrived from the address in use, which speaks against the move.
    fn contradicted(&mut self) {
        if let Self::Proposed(probe) = *self {
            *self = Self::Retiring(probe);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// From the address already in use.
    Established,
    /// From somewhere new; a challenge is now outstanding against it.
    Probing(SocketAddr),
    /// From the candidate already being probed.
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answered {
    /// Nothing moved, but this side may now speak to it freely.
    Validated,
    Migrated(SocketAddr),
}

enum Standing {
    /// This side dialled it, or it answered a challenge.
    Proven,
    /// A source address and nothing more, with the budget it has earned.
    Claimed(Probe),
}

pub struct PathValidator {
    current: SocketAddr,
    standing: Standing,
    /// Independent of `standing`: a peer rebinding before it ever validated
    /// leaves an unproven address in use *and* a candidate.
    candidate: Option<(SocketAddr, Candidate)>,
}

impl PathValidator {
    /// Nothing to prove: the address came from the authenticated channel.
    #[must_use]
    pub const fn dialled(peer: SocketAddr) -> Self {
        Self {
            current: peer,
            standing: Standing::Proven,
            candidate: None,
        }
    }

    /// A claim: nothing owed until it sends, then [`AMPLIFICATION_LIMIT`]x.
    #[must_use]
    pub const fn claimed(peer: SocketAddr) -> Self {
        Self {
            current: peer,
            standing: Standing::Claimed(Probe::new()),
            candidate: None,
        }
    }

    #[must_use]
    pub const fn current(&self) -> SocketAddr {
        self.current
    }

    /// Against the address in use or against one proposing to replace it.
    #[must_use]
    pub const fn probing(&self) -> bool {
        matches!(&self.standing, Standing::Claimed(probe) if probe.challengeable())
            || matches!(&self.candidate, Some((_, next)) if next.probe().challengeable())
    }

    /// Authenticated is the precondition: the tag verified and the window
    /// admitted the number, so the peer's own keys vouched for it.
    pub fn arrived(&mut self, from: SocketAddr, bytes: usize, now: Instant) -> Arrival {
        if from == self.current {
            // Evidence, not proof: a datagram sealed before a rebind arrives
            // after it, and cancelling would destroy the token being answered.
            if let Some((_, candidate)) = &mut self.candidate {
                candidate.contradicted();
            }
            if let Standing::Claimed(probe) = &mut self.standing {
                probe.arrived(bytes, now);
            }
            return Arrival::Established;
        }
        match &mut self.candidate {
            Some((at, candidate)) if *at == from => {
                candidate.arrived(bytes, now);
                Arrival::Pending
            }
            _ => {
                let mut probe = Probe::new();
                probe.arrived(bytes, now);
                self.candidate = Some((from, Candidate::Proposed(probe)));
                Arrival::Probing(from)
            }
        }
    }

    /// Charged through [`spent`](Self::spent), which keeps the amplification
    /// bound honest. The address in use goes first when it is the unproven one.
    pub fn poll_challenge(&mut self, now: Instant) -> Option<(SocketAddr, [u8; 8])> {
        let current = self.current;
        if let Standing::Claimed(probe) = &mut self.standing
            && let Some(token) = probe.challenge(now)
        {
            return Some((current, token));
        }
        let (at, candidate) = self.candidate.as_mut()?;
        let at = *at;
        if let Some(token) = candidate.probe_mut().challenge(now) {
            return Some((at, token));
        }
        // The address in use is never dropped: there is no fallback.
        if candidate.probe().sent >= PROBE_LIMIT {
            self.candidate = None;
        }
        None
    }

    #[must_use]
    pub fn challenge_deadline(&self) -> Option<Instant> {
        let claimed = match &self.standing {
            Standing::Proven => None,
            Standing::Claimed(probe) => probe.deadline(),
        };
        let candidate = self
            .candidate
            .as_ref()
            .and_then(|(_, candidate)| candidate.probe().deadline());
        claimed.into_iter().chain(candidate).min()
    }

    /// An unanswered address may be sent what it has earned and no more.
    #[must_use]
    pub fn may_send(&self, to: SocketAddr, bytes: usize) -> bool {
        match self.unproven(to) {
            Some(probe) => probe.credit >= bytes as u64,
            None => to == self.current,
        }
    }

    pub fn spent(&mut self, to: SocketAddr, bytes: usize) {
        if let Some(probe) = self.unproven_mut(to) {
            probe.credit = probe.credit.saturating_sub(bytes as u64);
        }
    }

    fn unproven(&self, to: SocketAddr) -> Option<&Probe> {
        if to == self.current {
            return match &self.standing {
                Standing::Proven => None,
                Standing::Claimed(probe) => Some(probe),
            };
        }
        match &self.candidate {
            Some((at, candidate)) if *at == to => Some(candidate.probe()),
            _ => None,
        }
    }

    fn unproven_mut(&mut self, to: SocketAddr) -> Option<&mut Probe> {
        if to == self.current {
            return match &mut self.standing {
                Standing::Proven => None,
                Standing::Claimed(probe) => Some(probe),
            };
        }
        match &mut self.candidate {
            Some((at, candidate)) if *at == to => Some(candidate.probe_mut()),
            _ => None,
        }
    }

    /// The address is checked as well as the token: the right token from the
    /// wrong place is exactly what an attacker relaying one achieves.
    pub fn answered(&mut self, from: SocketAddr, token: [u8; 8]) -> Option<Answered> {
        if from == self.current
            && let Standing::Claimed(probe) = &self.standing
            && probe.token == Some(token)
        {
            self.standing = Standing::Proven;
            return Some(Answered::Validated);
        }
        let (at, candidate) = self.candidate.as_ref()?;
        if *at != from || candidate.probe().token != Some(token) {
            return None;
        }
        self.candidate = None;
        self.current = from;
        self.standing = Standing::Proven;
        Some(Answered::Migrated(from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last], 4000))
    }

    #[test]
    fn a_new_address_is_probed_before_it_is_used() {
        let now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        assert_eq!(path.arrived(addr(1), 100, now), Arrival::Established);
        assert!(!path.probing(), "a dialled address has nothing to prove");
        assert_eq!(path.arrived(addr(2), 100, now), Arrival::Probing(addr(2)));
        assert_eq!(path.current(), addr(1), "the working path is kept");
        let (to, token) = path.poll_challenge(now).expect("a challenge is due");
        assert_eq!(to, addr(2));
        assert_eq!(
            path.answered(addr(2), token),
            Some(Answered::Migrated(addr(2)))
        );
        assert_eq!(path.current(), addr(2));
    }

    /// Else a network change is at the mercy of the entropy pool.
    #[test]
    fn a_candidate_costs_no_entropy_until_it_is_challenged() {
        let now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        path.arrived(addr(2), 100, now);
        assert_eq!(path.answered(addr(2), [0; 8]), None);
        let (_, token) = path.poll_challenge(now).expect("a challenge is due");
        assert_eq!(
            path.poll_challenge(now + PROBE_INTERVAL),
            Some((addr(2), token)),
            "one token for the candidate, so an answer to any copy counts"
        );
    }

    /// A relay proves the token travelled, not who holds the address.
    #[test]
    fn a_response_moves_the_path_only_from_the_challenged_address() {
        let now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        path.arrived(addr(2), 100, now);
        let (_, token) = path.poll_challenge(now).expect("a challenge is due");
        let mut wrong = token;
        wrong[0] ^= 1;
        assert_eq!(path.answered(addr(2), wrong), None);
        assert_eq!(path.answered(addr(3), token), None);
        assert_eq!(path.current(), addr(1));
    }

    #[test]
    fn an_unvalidated_address_is_capped_at_three_times_what_it_sent() {
        let now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        path.arrived(addr(2), 100, now);
        assert!(path.may_send(addr(2), 300));
        path.spent(addr(2), 300);
        assert!(!path.may_send(addr(2), 1));
        assert!(path.may_send(addr(1), 100_000), "dialled has no budget");
    }

    /// A source address is whatever the sender wrote there.
    #[test]
    fn a_claimed_address_is_owed_nothing_until_it_has_sent_something() {
        let now = Instant::now();
        let mut path = PathValidator::claimed(addr(1));
        assert!(!path.may_send(addr(1), 1));
        assert_eq!(path.poll_challenge(now), None, "nothing has paid for one");
        assert_eq!(path.challenge_deadline(), None);

        path.arrived(addr(1), 100, now);
        assert!(path.may_send(addr(1), 300));
        assert!(!path.may_send(addr(1), 301));
    }

    #[test]
    fn a_claimed_address_that_answers_is_freed_without_migrating() {
        let now = Instant::now();
        let mut path = PathValidator::claimed(addr(1));
        path.arrived(addr(1), 100, now);
        let (to, token) = path.poll_challenge(now).expect("a challenge is due");
        assert_eq!(to, addr(1));
        assert_eq!(path.answered(addr(1), token), Some(Answered::Validated));
        assert_eq!(path.current(), addr(1));
        assert!(!path.probing());
        assert!(path.may_send(addr(1), 100_000), "proved has no budget");
    }

    /// Two unproven addresses; the one it is sending from has to win.
    #[test]
    fn a_claimed_address_and_a_candidate_are_challenged_side_by_side() {
        let now = Instant::now();
        let mut path = PathValidator::claimed(addr(1));
        path.arrived(addr(1), 100, now);
        assert_eq!(path.arrived(addr(2), 100, now), Arrival::Probing(addr(2)));
        let (first, _) = path.poll_challenge(now).expect("the address in use");
        assert_eq!(first, addr(1));
        let (second, token) = path.poll_challenge(now).expect("and the candidate");
        assert_eq!(second, addr(2));
        assert_eq!(
            path.answered(addr(2), token),
            Some(Answered::Migrated(addr(2)))
        );
        assert_eq!(path.current(), addr(2));
        assert!(!path.probing(), "and the claim it left is gone with it");
    }

    #[test]
    fn a_challenge_is_repeated_on_a_schedule_and_then_given_up_on() {
        let mut now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        path.arrived(addr(2), 100, now);
        for _ in 0..PROBE_LIMIT {
            assert!(path.poll_challenge(now).is_some());
            assert!(path.poll_challenge(now).is_none(), "not before it is due");
            now += PROBE_INTERVAL;
        }
        assert_eq!(path.poll_challenge(now), None);
        assert!(!path.probing(), "a silent candidate is dropped");
        assert_eq!(path.current(), addr(1));
    }

    /// The address in use is not a candidate and cannot be dropped.
    #[test]
    fn a_claimed_address_that_never_answers_stays_claimed() {
        let mut now = Instant::now();
        let mut path = PathValidator::claimed(addr(1));
        path.arrived(addr(1), 1000, now);
        for _ in 0..PROBE_LIMIT {
            assert!(path.poll_challenge(now).is_some());
            now += PROBE_INTERVAL;
        }
        assert_eq!(path.poll_challenge(now), None);
        assert!(!path.probing(), "out of chances until it speaks again");
        assert!(!path.may_send(addr(1), 3001), "and still under the bound");

        path.arrived(addr(1), 1000, now);
        assert!(path.probing());
        assert!(path.poll_challenge(now).is_some());
    }

    /// Tracking both would be a budget an attacker gets to allocate.
    #[test]
    fn a_second_candidate_replaces_the_first() {
        let now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        path.arrived(addr(2), 100, now);
        let (_, token) = path.poll_challenge(now).expect("a challenge is due");
        assert_eq!(path.arrived(addr(3), 100, now), Arrival::Probing(addr(3)));
        assert_eq!(path.answered(addr(2), token), None);
    }

    /// Both paths are briefly live; dropping on a straggler restarts the move.
    #[test]
    fn a_straggler_from_the_address_in_use_does_not_cancel_a_challenge() {
        let now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        path.arrived(addr(2), 100, now);
        let (to, token) = path.poll_challenge(now).expect("a challenge is due");
        assert_eq!(to, addr(2));

        assert_eq!(path.arrived(addr(1), 100, now), Arrival::Established);
        assert!(path.probing(), "the challenge is still outstanding");

        assert_eq!(
            path.answered(addr(2), token),
            Some(Answered::Migrated(addr(2))),
            "and the answer to it completes the move"
        );
        assert_eq!(path.current(), addr(2));
        assert!(!path.probing());
    }

    /// What the grace must not cost: a contradicted candidate buys nothing.
    #[test]
    fn sustained_traffic_on_the_working_path_retires_a_silent_candidate() {
        let mut now = Instant::now();
        let mut path = PathValidator::dialled(addr(1));
        path.arrived(addr(2), 100, now);
        let (_, token) = path.poll_challenge(now).expect("a challenge is due");
        now += PROBE_INTERVAL;
        for _ in 1..PROBE_LIMIT {
            assert_eq!(path.arrived(addr(1), 100, now), Arrival::Established);
            assert_eq!(path.arrived(addr(2), 100, now), Arrival::Pending);
            assert!(path.poll_challenge(now).is_some(), "chances it had left");
            now += PROBE_INTERVAL;
        }
        assert_eq!(path.arrived(addr(2), 100, now), Arrival::Pending);
        assert_eq!(path.poll_challenge(now), None);
        assert!(!path.probing(), "the candidate ran out of chances");
        assert_eq!(path.answered(addr(2), token), None, "its token is dead");
        assert_eq!(path.current(), addr(1));
    }
}
