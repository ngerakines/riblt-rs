use crate::coded_symbol::CodedSymbol;
use crate::mapping::RandomMapping;
use crate::symbol::{ChecksumHash, HashedSymbol, Symbol};

/// A fixed-size batch of coded symbols for standalone IBLT operations.
///
/// Unlike the streaming [`Encoder`](crate::Encoder)/[`Decoder`](crate::Decoder) pair,
/// a `Sketch` has a predetermined size. Two sketches of the same size can be subtracted
/// to produce a sketch representing their symmetric difference, which can then be decoded.
pub struct Sketch<T: Symbol> {
    symbols: Vec<CodedSymbol<T>>,
}

impl<T: Symbol> Sketch<T> {
    /// Create a new sketch with the given number of coded symbols.
    pub fn new(size: usize) -> Self {
        Self {
            symbols: (0..size).map(|_| CodedSymbol::default()).collect(),
        }
    }

    /// Add a source symbol to the sketch.
    pub fn add_symbol(&mut self, s: T) {
        self.add_hashed_symbol(&HashedSymbol::new(s));
    }

    /// Add a pre-hashed source symbol to the sketch.
    pub fn add_hashed_symbol(&mut self, s: &HashedSymbol<T>) {
        let len = self.symbols.len();
        let mut mapping = RandomMapping::new(s.mapping_seed);
        loop {
            let idx = mapping.next_index();
            if idx >= len {
                break;
            }
            self.symbols[idx].apply(s, 1);
        }
    }

    /// Remove a source symbol from the sketch.
    pub fn remove_hashed_symbol(&mut self, s: &HashedSymbol<T>) {
        let len = self.symbols.len();
        let mut mapping = RandomMapping::new(s.mapping_seed);
        loop {
            let idx = mapping.next_index();
            if idx >= len {
                break;
            }
            self.symbols[idx].apply(s, -1);
        }
    }

    /// Subtract another sketch from this one, producing the symmetric difference.
    pub fn subtract(&mut self, other: &Sketch<T>) {
        assert_eq!(
            self.symbols.len(),
            other.symbols.len(),
            "sketches must be the same size"
        );
        for (a, b) in self.symbols.iter_mut().zip(other.symbols.iter()) {
            a.symbol = a.symbol.xor(&b.symbol);
            a.hash = a.hash.uncombine(&b.hash);
            a.count -= b.count;
        }
    }

    /// Attempt to decode the sketch, recovering the symmetric difference.
    ///
    /// Returns `(forward, reverse, success)` where:
    /// - `forward`: symbols with count +1 (in the first set but not the second)
    /// - `reverse`: symbols with count -1 (in the second set but not the first)
    /// - `success`: whether all coded symbols were resolved
    pub fn decode(&mut self) -> (Vec<HashedSymbol<T>>, Vec<HashedSymbol<T>>, bool) {
        let mut forward = Vec::new();
        let mut reverse = Vec::new();
        let len = self.symbols.len();

        loop {
            let mut progress = false;

            for i in 0..len {
                if self.symbols[i].is_zero() {
                    continue;
                }
                if !self.symbols[i].is_pure() {
                    continue;
                }

                let sym = T::default().xor(&self.symbols[i].symbol);
                let hash = if self.symbols[i].count == 1 {
                    self.symbols[i].hash.clone()
                } else {
                    self.symbols[i].hash.negate()
                };
                let s = HashedSymbol {
                    symbol: sym.clone(),
                    hash,
                    mapping_seed: sym.mapping_seed(),
                };

                let direction = if self.symbols[i].count == 1 {
                    forward.push(s.clone());
                    -1
                } else {
                    reverse.push(s.clone());
                    1
                };

                // Peel this symbol from all coded symbols it maps to
                let mut mapping = RandomMapping::new(s.mapping_seed);
                loop {
                    let idx = mapping.next_index();
                    if idx >= len {
                        break;
                    }
                    self.symbols[idx].apply(&s, direction);
                }

                progress = true;
            }

            if !progress {
                break;
            }
        }

        let success = self.symbols.iter().all(|c| c.is_zero());
        (forward, reverse, success)
    }
}
