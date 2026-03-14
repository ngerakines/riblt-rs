use std::hash::{DefaultHasher, Hash, Hasher};

use crate::Symbol;

/// A variable-length byte string symbol for use with RIBLT.
///
/// XOR pads the shorter operand with zeros. Hash uses SipHash (non-homomorphic).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ByteSymbol(pub Vec<u8>);

impl Symbol for ByteSymbol {
    fn xor(&self, other: &Self) -> Self {
        let len = self.0.len().max(other.0.len());
        let mut result = vec![0u8; len];
        for (i, b) in self.0.iter().enumerate() {
            result[i] ^= b;
        }
        for (i, b) in other.0.iter().enumerate() {
            result[i] ^= b;
        }
        // Trim trailing zeros to keep canonical form
        while result.last() == Some(&0) {
            result.pop();
        }
        ByteSymbol(result)
    }

    fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}
