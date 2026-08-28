#![forbid(unsafe_code)]

//! Which packet numbers this endpoint has already accepted. Sliding rather
//! than a set, so memory stays bounded across a weeks-long session; the width
//! is how much reordering the link may do before a datagram is too old.

/// Packet numbers behind the newest one that are still individually tracked.
pub const WIDTH: u32 = 256;

const WORDS: usize = (WIDTH / u64::BITS) as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Never seen. The only answer that lets a datagram through.
    Fresh,
    Replay,
    /// Behind the window, so indistinguishable from a replay and refused.
    TooOld,
}

/// Zero is a real packet number, so `top == 0` cannot mean "none yet": bit
/// zero of the map is what says whether packet zero arrived.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    top: u64,
    seen: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            top: 0,
            seen: [0; WORDS],
        }
    }

    /// One call rather than a check and a commit: a split pair is a pair
    /// somebody eventually forgets to close.
    pub fn admit(&mut self, number: u64) -> Admission {
        if number > self.top {
            self.slide(number - self.top);
            self.top = number;
            self.set(0);
            return Admission::Fresh;
        }
        let behind = self.top - number;
        if behind >= u64::from(WIDTH) {
            return Admission::TooOld;
        }
        // `behind` is bounded by WIDTH just above, so the cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let behind = behind as u32;
        if self.get(behind) {
            return Admission::Replay;
        }
        self.set(behind);
        Admission::Fresh
    }

    /// The highest number accepted, or zero before anything has been.
    #[must_use]
    pub const fn top(&self) -> u64 {
        self.top
    }

    /// The window is already exactly this, so a second copy kept for
    /// acknowledging would be two answers to one question.
    #[must_use]
    pub const fn acknowledgement(&self) -> Option<(u64, u64)> {
        if !self.get(0) {
            return None;
        }
        // Bit *i* of the map is the number `i + 1` behind the top, which is
        // bit `i + 1` of this bitmap.
        Some((self.top, (self.seen[0] >> 1) | (self.seen[1] << 63)))
    }

    fn slide(&mut self, by: u64) {
        if by >= u64::from(WIDTH) {
            self.seen = [0; WORDS];
            return;
        }
        // Bounded by WIDTH above.
        #[allow(clippy::cast_possible_truncation)]
        let by = by as u32;
        let words = (by / u64::BITS) as usize;
        let bits = by % u64::BITS;
        if words > 0 {
            for index in (0..WORDS).rev() {
                self.seen[index] = if index >= words {
                    self.seen[index - words]
                } else {
                    0
                };
            }
        }
        if bits > 0 {
            let mut carry = 0u64;
            for word in &mut self.seen {
                let shifted = (*word << bits) | carry;
                carry = *word >> (u64::BITS - bits);
                *word = shifted;
            }
        }
    }

    fn set(&mut self, behind: u32) {
        let (word, bit) = Self::position(behind);
        self.seen[word] |= bit;
    }

    const fn get(&self, behind: u32) -> bool {
        let (word, bit) = Self::position(behind);
        self.seen[word] & bit != 0
    }

    const fn position(behind: u32) -> (usize, u64) {
        ((behind / u64::BITS) as usize, 1u64 << (behind % u64::BITS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Getting this wrong acknowledges a packet that was never sent.
    #[test]
    fn a_window_that_has_admitted_nothing_acknowledges_nothing() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.acknowledgement(), None);
        assert_eq!(window.admit(0), Admission::Fresh);
        assert_eq!(window.admit(0), Admission::Replay);
        assert_eq!(window.acknowledgement(), Some((0, 0)));
    }

    /// Sixty-four back crosses the word boundary the window is built from.
    #[test]
    fn an_acknowledgement_names_the_top_and_the_gaps_behind_it() {
        let mut window = ReplayWindow::new();
        for number in [0, 1, 3, 6] {
            window.admit(number);
        }
        // Bit zero is five (missing), four missing, three arrived, two missing.
        assert_eq!(window.acknowledgement(), Some((6, 0b0011_0100)));

        let mut window = ReplayWindow::new();
        window.admit(0);
        window.admit(64);
        assert_eq!(
            window.acknowledgement(),
            Some((64, 1 << 63)),
            "number zero is sixty-four behind"
        );
        window.admit(65);
        assert_eq!(window.acknowledgement(), Some((65, 1 << 0)));
    }

    /// Catches a shift that only moves whole words and leaves stale bits.
    #[test]
    fn a_jump_clears_everything_it_shifts_past() {
        let mut window = ReplayWindow::new();
        for number in 0..100 {
            assert_eq!(window.admit(number), Admission::Fresh);
        }
        assert_eq!(window.admit(5_000), Admission::Fresh);
        assert_eq!(window.admit(4_999), Admission::Fresh);
        assert_eq!(window.admit(4_999), Admission::Replay);
    }

    /// Differential test against a set with no interesting state to get wrong.
    #[test]
    fn the_bitmap_agrees_with_a_set_that_remembers_everything() {
        let mut window = ReplayWindow::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut top = 0u64;
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..200_000 {
            // xorshift64*: reproducible without a dependency.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let step = state.wrapping_mul(0x2545_f491_4f6c_dd1d) % 512;
            let number = top.saturating_sub(256).saturating_add(step);
            let expected = if number + u64::from(WIDTH) <= top {
                Admission::TooOld
            } else if seen.contains(&number) {
                Admission::Replay
            } else {
                Admission::Fresh
            };
            assert_eq!(window.admit(number), expected, "number {number}, top {top}");
            if expected == Admission::Fresh {
                seen.insert(number);
                top = top.max(number);
            }
        }
    }
}
