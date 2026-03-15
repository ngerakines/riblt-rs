use crate::symbol::{ChecksumHash, HashKey, HashedSymbol, Symbol};

/// A coded symbol produced by the RIBLT encoder.
///
/// Each coded symbol is the XOR-combination of a pseudo-random subset of source symbols.
/// It contains the XOR of their values, combined checksums, and a net count.
#[derive(Debug, Clone)]
pub struct CodedSymbol<T: Symbol> {
    /// XOR of all source symbols mapped to this coded symbol.
    pub symbol: T,
    /// Combined checksum of all source symbol hashes.
    pub hash: T::Checksum,
    /// Net count of source symbols (positive for encoder-side, negative for decoder-side).
    pub count: i64,
}

impl<T: Symbol> Default for CodedSymbol<T> {
    fn default() -> Self {
        Self {
            symbol: T::default(),
            hash: T::Checksum::default(),
            count: 0,
        }
    }
}

impl<T: Symbol> CodedSymbol<T> {
    /// Apply a source symbol to this coded symbol.
    ///
    /// `direction` is `1` to add or `-1` to remove.
    pub fn apply(&mut self, s: &HashedSymbol<T>, direction: i64) {
        self.symbol = self.symbol.xor(&s.symbol);
        if direction >= 0 {
            self.hash = self.hash.combine(&s.hash);
        } else {
            self.hash = self.hash.uncombine(&s.hash);
        }
        self.count += direction;
    }

    /// Returns `true` if this coded symbol contains exactly one source symbol
    /// and the hash is consistent.
    pub fn is_pure(&self) -> bool {
        self.is_pure_with_key(None)
    }

    /// Returns `true` if this coded symbol contains exactly one source symbol
    /// and the hash is consistent, using a keyed hash if provided.
    pub fn is_pure_with_key(&self, key: Option<&HashKey>) -> bool {
        let expected = match key {
            Some(k) => self.symbol.keyed_hash(k),
            None => self.symbol.hash(),
        };
        match self.count {
            1 => self.hash == expected,
            -1 => self.hash == expected.negate(),
            _ => false,
        }
    }

    /// Returns `true` if this coded symbol is empty (all symbols cancelled out).
    pub fn is_zero(&self) -> bool {
        self.count == 0 && self.hash.is_zero()
    }
}
