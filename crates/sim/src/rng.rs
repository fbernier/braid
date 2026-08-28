#![forbid(unsafe_code)]

//! `splitmix64`, verbatim from the reference implementation.
//!
//! Not `rand`: a committed seed has to reproduce its run across dependency
//! version bumps, which `rand` does not promise.

pub struct Rng(u64);

impl Rng {
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `bound`, or zero when there is no such number.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    /// Whether an event of probability `percent` happens.
    pub fn chance(&mut self, percent: u8) -> bool {
        self.below(100) < u64::from(percent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_reproduces_its_sequence_and_two_seeds_do_not_agree() {
        let mut first = Rng::seeded(7);
        let mut second = Rng::seeded(7);
        for _ in 0..1000 {
            assert_eq!(first.next_u64(), second.next_u64());
        }
        assert_ne!(Rng::seeded(7).next_u64(), Rng::seeded(8).next_u64());
    }
}
