//! Deterministic pseudo-random generator.
//!
//! Hard rule 1 (CLAUDE-fuzz.md): "Same seed, same operation sequence, same
//! result." We do not use the `rand` crate because its algorithms and seeding
//! are not guaranteed stable across crate versions, which would break replay of
//! a recorded seed after a dependency bump. SplitMix64 is a fixed, well-known
//! algorithm with no hidden state, so a `(seed, libreg commit)` pair fully
//! determines the run on any platform (little or big endian: we only ever do
//! wrapping u64 arithmetic, never reinterpret bytes).

/// SplitMix64. See Steele, Lea, Flood (2014). Each call advances `state` by the
/// golden-gamma constant and mixes, giving a full-period 64-bit stream.
#[derive(Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    /// Next raw 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform integer in `[0, n)`. `n == 0` returns 0. Uses Lemire-style
    /// rejection so the distribution has no modulo bias.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Rejection threshold: discard the short final interval so every
        // residue class is equally likely.
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }

    /// Inclusive range `[lo, hi]`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.below(hi - lo + 1)
    }

    /// True with probability `num/den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    /// Pick an index into a slice of cumulative weights. `cum` must be
    /// non-decreasing and end at the total weight. Returns the first index whose
    /// cumulative weight exceeds the roll.
    pub fn weighted(&mut self, cum: &[u64]) -> usize {
        let total = *cum.last().unwrap_or(&0);
        if total == 0 {
            return 0;
        }
        let roll = self.below(total);
        cum.iter().position(|&c| roll < c).unwrap_or(cum.len() - 1)
    }

    /// Borrow a uniformly chosen element of a non-empty slice.
    pub fn choice<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let i = self.below(items.len() as u64) as usize;
        &items[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_seed() {
        let mut a = Rng::new(0xDEAD_BEEF);
        let mut b = Rng::new(0xDEAD_BEEF);
        for _ in 0..10_000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        // Overwhelmingly likely to differ within a few draws.
        let differ = (0..8).any(|_| a.next_u64() != b.next_u64());
        assert!(differ);
    }

    #[test]
    fn below_is_in_range() {
        let mut r = Rng::new(42);
        for _ in 0..10_000 {
            assert!(r.below(7) < 7);
        }
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
    }

    #[test]
    fn range_inclusive() {
        let mut r = Rng::new(99);
        for _ in 0..10_000 {
            let v = r.range(5, 10);
            assert!((5..=10).contains(&v));
        }
        assert_eq!(r.range(3, 3), 3);
        assert_eq!(r.range(8, 2), 8); // hi <= lo clamps to lo
    }

    #[test]
    fn weighted_respects_zero_weight_buckets() {
        // Buckets: [0, 5, 0] -> cumulative [0, 5, 5]. Only index 1 is reachable.
        let cum = [0u64, 5, 5];
        let mut r = Rng::new(7);
        for _ in 0..1000 {
            assert_eq!(r.weighted(&cum), 1);
        }
    }
}
