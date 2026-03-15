use crate::coded_symbol::CodedSymbol;
use crate::symbol::{HashKey, HashedSymbol, Symbol};
use crate::window::CodingWindow;

/// Generates an infinite sequence of coded symbols for a set of source symbols.
///
/// # Usage
///
/// 1. Add all source symbols via [`Encoder::add_symbol`].
/// 2. Call [`Encoder::produce_next_coded_symbol`] repeatedly to generate coded symbols.
/// 3. Stream the coded symbols to a [`Decoder`](crate::Decoder).
///
/// Once you begin producing coded symbols, do not add more source symbols.
///
/// # Keyed hashing
///
/// Use [`Encoder::with_key`] to protect against adversarial workloads.
/// Both encoder and decoder must use the same key.
///
/// # Example
///
/// ```
/// use riblt::{Encoder, Symbol};
///
/// # #[derive(Clone, Default, Debug)]
/// # struct MySymbol(u64);
/// # impl Symbol for MySymbol {
/// #     fn xor(&self, other: &Self) -> Self { MySymbol(self.0 ^ other.0) }
/// #     fn hash(&self) -> u64 {
/// #         let mut h = self.0;
/// #         h ^= h >> 33; h = h.wrapping_mul(0xff51afd7ed558ccd);
/// #         h ^= h >> 33; h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
/// #         h ^= h >> 33; h
/// #     }
/// # }
/// let mut enc = Encoder::new();
/// enc.add_symbol(MySymbol(1));
/// enc.add_symbol(MySymbol(2));
/// enc.add_symbol(MySymbol(3));
///
/// let c0 = enc.produce_next_coded_symbol();
/// let c1 = enc.produce_next_coded_symbol();
/// // ... continue streaming
/// ```
pub struct Encoder<T: Symbol> {
    window: CodingWindow<T>,
    key: Option<HashKey>,
}

impl<T: Symbol> Encoder<T> {
    pub fn new() -> Self {
        Self {
            window: CodingWindow::new(),
            key: None,
        }
    }

    /// Create an encoder with a keyed hash function for adversarial resilience.
    ///
    /// The decoder must use the same key.
    pub fn with_key(key: HashKey) -> Self {
        Self {
            window: CodingWindow::new(),
            key: Some(key),
        }
    }

    /// Add a source symbol to the encoder's set.
    ///
    /// Must be called before any [`produce_next_coded_symbol`](Self::produce_next_coded_symbol).
    pub fn add_symbol(&mut self, s: T) {
        let hs = match &self.key {
            Some(k) => HashedSymbol::new_keyed(s, k),
            None => HashedSymbol::new(s),
        };
        self.add_hashed_symbol(hs);
    }

    /// Add a pre-hashed source symbol.
    pub fn add_hashed_symbol(&mut self, s: HashedSymbol<T>) {
        self.window.add_hashed_symbol(s);
    }

    /// Generate the next coded symbol in the sequence.
    ///
    /// Each call produces the next symbol in an infinite, deterministic stream.
    pub fn produce_next_coded_symbol(&mut self) -> CodedSymbol<T> {
        let mut coded = CodedSymbol::default();
        self.window.apply_window(&mut coded, 1);
        coded
    }

    /// Reset the encoder, clearing all symbols.
    pub fn reset(&mut self) {
        self.window.reset();
    }
}

impl<T: Symbol> Default for Encoder<T> {
    fn default() -> Self {
        Self::new()
    }
}
