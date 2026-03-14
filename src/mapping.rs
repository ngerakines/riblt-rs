/// Pseudo-random mapping from a symbol hash to an infinite sequence of coded symbol indices.
///
/// Each symbol deterministically maps to a subset of coded symbol indices. The distribution
/// ensures that index `i` is visited with probability roughly `1 / (1 + i/2)`, so early
/// coded symbols have higher degree (more source symbols mapped to them).
#[derive(Debug, Clone)]
pub struct RandomMapping {
    prng: u64,
    last_index: usize,
}

/// LCG multiplier constant from the reference implementation.
const LCG_MULTIPLIER: u64 = 0xda942042e4dd58b5;

impl RandomMapping {
    /// Create a new mapping seeded by a symbol hash.
    ///
    /// The initial `last_index` is 0, meaning the symbol always maps to coded symbol 0 first.
    pub fn new(hash: u64) -> Self {
        Self {
            prng: hash,
            last_index: 0,
        }
    }

    /// Returns the current (most recently generated) index.
    pub fn last_index(&self) -> usize {
        self.last_index
    }

    /// Advance the PRNG and compute the next coded symbol index.
    ///
    /// Mirrors the Go implementation exactly:
    /// ```text
    /// prng *= 0xda942042e4dd58b5
    /// lastIndex += ceil((lastIndex + 1.5) * (2^32 / sqrt(prng + 1) - 1))
    /// ```
    pub fn next_index(&mut self) -> usize {
        self.prng = self.prng.wrapping_mul(LCG_MULTIPLIER);
        let base = self.last_index as f64 + 1.5;
        let gap = base * (((1u64 << 32) as f64 / (self.prng as f64 + 1.0).sqrt()) - 1.0);
        let gap = gap.ceil().max(1.0) as usize;
        self.last_index = self.last_index.saturating_add(gap);
        self.last_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_index_is_zero() {
        let m = RandomMapping::new(42);
        assert_eq!(m.last_index(), 0);
    }

    #[test]
    fn next_index_increases() {
        let mut m = RandomMapping::new(12345);
        let first = m.next_index();
        assert!(first > 0, "first next_index should be > 0");
        let second = m.next_index();
        assert!(second > first, "indices must increase: {second} > {first}");
    }

    #[test]
    fn different_seeds_produce_different_sequences() {
        let mut m1 = RandomMapping::new(1);
        let mut m2 = RandomMapping::new(2);
        let seq1: Vec<_> = (0..5).map(|_| m1.next_index()).collect();
        let seq2: Vec<_> = (0..5).map(|_| m2.next_index()).collect();
        assert_ne!(seq1, seq2);
    }

    #[test]
    fn same_seed_is_deterministic() {
        let mut m1 = RandomMapping::new(999);
        let mut m2 = RandomMapping::new(999);
        let seq1: Vec<_> = (0..10).map(|_| m1.next_index()).collect();
        let seq2: Vec<_> = (0..10).map(|_| m2.next_index()).collect();
        assert_eq!(seq1, seq2);
    }
}
