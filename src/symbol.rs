/// 16-byte key for keyed hashing, protecting against adversarial workloads.
///
/// Both encoder and decoder must use the same key. Generate randomly per-session
/// and share out-of-band (e.g., during connection setup).
pub type HashKey = [u8; 16];

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
    /// XOR group operation combining two symbols.
    fn xor(&self, other: &Self) -> Self;

    /// Non-homomorphic hash of this symbol.
    fn hash(&self) -> u64;

    /// Keyed non-homomorphic hash of this symbol.
    ///
    /// Using a random key makes the hash unpredictable to an adversary,
    /// preventing crafted inputs that degrade RIBLT performance.
    /// The default implementation ignores the key — override this for
    /// real protection.
    fn keyed_hash(&self, key: &HashKey) -> u64 {
        let _ = key;
        self.hash()
    }
}

/// A symbol paired with its pre-computed hash.
#[derive(Debug, Clone)]
pub struct HashedSymbol<T: Symbol> {
    pub symbol: T,
    pub hash: u64,
}

impl<T: Symbol> HashedSymbol<T> {
    pub fn new(symbol: T) -> Self {
        let hash = symbol.hash();
        Self { symbol, hash }
    }

    /// Create a hashed symbol using a keyed hash function.
    pub fn new_keyed(symbol: T, key: &HashKey) -> Self {
        let hash = symbol.keyed_hash(key);
        Self { symbol, hash }
    }
}

impl<T: Symbol> Default for HashedSymbol<T> {
    fn default() -> Self {
        Self {
            symbol: T::default(),
            hash: 0,
        }
    }
}
