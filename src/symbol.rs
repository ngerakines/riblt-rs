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
}

impl<T: Symbol> Default for HashedSymbol<T> {
    fn default() -> Self {
        Self {
            symbol: T::default(),
            hash: 0,
        }
    }
}
