#![forbid(unsafe_code)]

//! What the network is allowed to do to a datagram.

use crate::net::Side;
use crate::rng::Rng;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// After the link's own latency, and nothing else.
    Deliver,
    /// The sender is not told.
    Drop,
    /// Also how this harness reorders.
    Delay(Duration),
    /// As a router with two paths to the same place does.
    Duplicate,
    /// One bit flips, which must fail authentication rather than make a frame.
    Corrupt(u16),
    /// Cut short by a tunnel with a smaller MTU than the path advertised.
    Truncate(u16),
    /// Arrives now and again later, from a recording.
    Replay(Duration),
    /// The source address is rewritten, as an off-path attacker would.
    Spoof,
    /// The destination receives nothing at all until this expires: total, and
    /// with an end, which is what a keep-alive and a probe timeout must survive.
    Blackhole { until: Duration },
}

pub trait Schedule {
    fn next(&mut self, from: Side, datagram: &[u8]) -> Fault;
}

pub struct Perfect;

impl Schedule for Perfect {
    fn next(&mut self, _from: Side, _datagram: &[u8]) -> Fault {
        Fault::Deliver
    }
}

/// Two-state Markov burst loss: independent loss at 5% almost never drops four
/// in a row, and four in a row is what forces the ledger to a whole screen.
pub struct GilbertElliott {
    rng: Rng,
    bad: bool,
    /// Chance per datagram of entering the bad state from the good one.
    pub to_bad: u8,
    /// Chance per datagram of recovering.
    pub to_good: u8,
    /// Loss while good, and while bad.
    pub good_loss: u8,
    pub bad_loss: u8,
}

impl GilbertElliott {
    /// Usually fine and occasionally, briefly, not.
    #[must_use]
    pub const fn typical(seed: u64) -> Self {
        Self {
            rng: Rng::seeded(seed),
            bad: false,
            to_bad: 3,
            to_good: 40,
            good_loss: 1,
            bad_loss: 60,
        }
    }

    /// A link nobody would use, which the transport must still converge on.
    #[must_use]
    pub const fn hostile(seed: u64) -> Self {
        Self {
            rng: Rng::seeded(seed),
            bad: false,
            to_bad: 20,
            to_good: 15,
            good_loss: 10,
            bad_loss: 90,
        }
    }
}

impl Schedule for GilbertElliott {
    fn next(&mut self, _from: Side, _datagram: &[u8]) -> Fault {
        self.bad = if self.bad {
            !self.rng.chance(self.to_good)
        } else {
            self.rng.chance(self.to_bad)
        };
        let loss = if self.bad {
            self.bad_loss
        } else {
            self.good_loss
        };
        if self.rng.chance(loss) {
            return Fault::Drop;
        }
        // Jitter is what turns a burst into reordering.
        if self.bad && self.rng.chance(30) {
            return Fault::Delay(Duration::from_millis(20 + self.rng.below(180)));
        }
        if self.rng.chance(2) {
            return Fault::Duplicate;
        }
        Fault::Deliver
    }
}

/// A coverage-guided fuzzer's input *is* the interleaving it searches over.
pub struct Bytes<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Bytes<'a> {
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }

    fn take(&mut self) -> u8 {
        let byte = self.input.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        byte
    }
}

impl Schedule for Bytes<'_> {
    fn next(&mut self, _from: Side, _datagram: &[u8]) -> Fault {
        match self.take() {
            0..=180 => Fault::Deliver,
            181..=215 => Fault::Drop,
            216..=228 => Fault::Duplicate,
            229..=241 => Fault::Delay(Duration::from_millis(10 * u64::from(self.take() % 20 + 1))),
            242..=246 => Fault::Corrupt(u16::from(self.take())),
            247..=250 => Fault::Truncate(u16::from(self.take())),
            251..=252 => Fault::Replay(Duration::from_millis(500)),
            253..=254 => Fault::Spoof,
            // Bounded: every timer this reaches fires inside a second.
            255 => Fault::Blackhole {
                until: Duration::from_millis(200 * u64::from(self.take() % 10 + 1)),
            },
        }
    }
}

/// Loss towards the client with acknowledgements getting through is the state
/// in which a row that changed and changed back is invisible to a comparison.
pub struct Asymmetric<C, S> {
    pub from_client: C,
    pub from_server: S,
}

impl<C: Schedule, S: Schedule> Schedule for Asymmetric<C, S> {
    fn next(&mut self, from: Side, datagram: &[u8]) -> Fault {
        match from {
            Side::Client => self.from_client.next(from, datagram),
            Side::Server => self.from_server.next(from, datagram),
        }
    }
}

/// Silently carries nothing above `limit`: small datagrams keep crossing, so
/// the connection is alive by every measure while every screen disappears.
pub struct Narrows<S> {
    pub limit: usize,
    pub otherwise: S,
}

impl<S: Schedule> Schedule for Narrows<S> {
    fn next(&mut self, from: Side, datagram: &[u8]) -> Fault {
        if datagram.len() > self.limit {
            return Fault::Drop;
        }
        self.otherwise.next(from, datagram)
    }
}

/// A fixed sequence, reused from the end once it runs out.
pub struct Script {
    faults: Vec<Fault>,
    at: usize,
}

impl Script {
    #[must_use]
    pub fn new(faults: Vec<Fault>) -> Self {
        Self { faults, at: 0 }
    }
}

impl Schedule for Script {
    fn next(&mut self, _from: Side, _datagram: &[u8]) -> Fault {
        if self.faults.is_empty() {
            return Fault::Deliver;
        }
        let fault = self.faults[self.at.min(self.faults.len() - 1)];
        self.at += 1;
        fault
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole model exists for: bursts, not a coin flip.
    #[test]
    fn burst_loss_arrives_in_runs() {
        let mut schedule = GilbertElliott::hostile(1);
        let side = Side::Client;
        let mut longest = 0;
        let mut run = 0;
        for _ in 0..10_000 {
            if schedule.next(side, &[]) == Fault::Drop {
                run += 1;
                longest = longest.max(run);
            } else {
                run = 0;
            }
        }
        assert!(longest >= 4, "longest run of losses was {longest}");
    }

    /// A fuzzer hands over whatever it likes, including nothing.
    #[test]
    fn an_exhausted_byte_schedule_keeps_delivering() {
        let mut schedule = Bytes::new(&[]);
        assert_eq!(schedule.next(Side::Client, &[]), Fault::Deliver);
    }
}
