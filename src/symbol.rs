/// 16-byte key for keyed hashing, protecting against adversarial workloads.
///
/// Both encoder and decoder must use the same key. Generate randomly per-session
/// and share out-of-band (e.g., during connection setup).
pub type HashKey = [u8; 16];

/// A checksum value that can be combined with other checksums.
///
/// For the standard RIBLT, this is `u64` with XOR as the combine operation.
/// For ECMH, this is a ristretto255 curve point with point addition.
pub trait ChecksumHash: Clone + Default + PartialEq + std::fmt::Debug {
    /// Combine two checksums (XOR for u64, point addition for curve points).
    fn combine(&self, other: &Self) -> Self;

    /// Inverse of combine (XOR for u64, point subtraction for curve points).
    ///
    /// For self-inverse operations like XOR this is the same as `combine`.
    fn uncombine(&self, other: &Self) -> Self;

    /// Negate this checksum (for XOR this is identity, for curve points this is point negation).
    fn negate(&self) -> Self;

    /// Returns `true` if this is the identity/zero element.
    fn is_zero(&self) -> bool;
}

impl ChecksumHash for u64 {
    fn combine(&self, other: &Self) -> Self {
        self ^ other
    }

    fn uncombine(&self, other: &Self) -> Self {
        self ^ other // XOR is self-inverse
    }

    fn negate(&self) -> Self {
        *self // XOR is self-inverse, so negation is identity
    }

    fn is_zero(&self) -> bool {
        *self == 0
    }
}

/// A symbol that can participate in RIBLT set reconciliation.
///
/// Implementations must satisfy group properties under [`Symbol::xor`]:
/// - **Associativity**: `a.xor(&b).xor(&c) == a.xor(&b.xor(&c))`
/// - **Identity**: `a.xor(&T::default()) == a`
/// - **Self-inverse**: `a.xor(&a) == T::default()`
///
/// The [`Symbol::hash`] function must be **non-homomorphic** with respect to XOR:
/// `a.xor(&b).hash() != a.hash() ^ b.hash()` (with high probability).
/// This property is essential for correctness during decoding.
pub trait Symbol: Clone + Default {
    /// The checksum type used for integrity verification during decoding.
    type Checksum: ChecksumHash;

    /// XOR group operation combining two symbols.
    fn xor(&self, other: &Self) -> Self;

    /// Non-homomorphic hash of this symbol, used as the integrity checksum.
    fn hash(&self) -> Self::Checksum;

    /// Deterministic seed for the random mapping PRNG.
    ///
    /// This determines which coded symbols a source symbol maps to.
    /// For `u64` checksums this typically returns the same value as `hash()`.
    /// For ECMH checksums this returns a separate `u64` derived from the symbol data.
    fn mapping_seed(&self) -> u64;

    /// Keyed non-homomorphic hash of this symbol.
    ///
    /// Using a random key makes the hash unpredictable to an adversary,
    /// preventing crafted inputs that degrade RIBLT performance.
    /// The default implementation ignores the key — override this for
    /// real protection.
    fn keyed_hash(&self, key: &HashKey) -> Self::Checksum {
        let _ = key;
        self.hash()
    }

    /// Keyed mapping seed.
    ///
    /// The default implementation ignores the key.
    fn keyed_mapping_seed(&self, key: &HashKey) -> u64 {
        let _ = key;
        self.mapping_seed()
    }
}

/// A symbol paired with its pre-computed hash and mapping seed.
#[derive(Debug, Clone)]
pub struct HashedSymbol<T: Symbol> {
    pub symbol: T,
    pub hash: T::Checksum,
    pub mapping_seed: u64,
}

impl<T: Symbol> HashedSymbol<T> {
    pub fn new(symbol: T) -> Self {
        let hash = symbol.hash();
        let mapping_seed = symbol.mapping_seed();
        Self {
            symbol,
            hash,
            mapping_seed,
        }
    }

    /// Create a hashed symbol using a keyed hash function.
    pub fn new_keyed(symbol: T, key: &HashKey) -> Self {
        let hash = symbol.keyed_hash(key);
        let mapping_seed = symbol.keyed_mapping_seed(key);
        Self {
            symbol,
            hash,
            mapping_seed,
        }
    }
}

impl<T: Symbol> Default for HashedSymbol<T> {
    fn default() -> Self {
        Self {
            symbol: T::default(),
            hash: T::Checksum::default(),
            mapping_seed: 0,
        }
    }
}
