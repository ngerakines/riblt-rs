use crate::coded_symbol::CodedSymbol;
use crate::symbol::{HashedSymbol, Symbol};
use crate::window::CodingWindow;

/// Recovers the symmetric difference between two sets by processing coded symbols.
///
/// The decoder holds one party's local set and receives coded symbols produced by
/// an [`Encoder`](crate::Encoder) holding the other party's set. After receiving
/// enough coded symbols (approximately 1.35x the symmetric difference size),
/// the decoder can recover which symbols are exclusive to each set.
///
/// # Usage
///
/// 1. Add all local symbols via [`Decoder::add_symbol`].
/// 2. Receive coded symbols from the encoder and pass them to [`Decoder::add_coded_symbol`].
/// 3. After each coded symbol, call [`Decoder::try_decode`] to attempt peeling.
/// 4. Check [`Decoder::decoded`] to see if reconciliation is complete.
/// 5. Retrieve results with [`Decoder::local`] and [`Decoder::remote`].
pub struct Decoder<T: Symbol> {
    coded_symbols: Vec<CodedSymbol<T>>,
    /// Window for the decoder's initial local set.
    window: CodingWindow<T>,
    /// Symbols discovered to be exclusive to the decoder's set (B \ A).
    local_window: CodingWindow<T>,
    /// Symbols discovered to be exclusive to the encoder's set (A \ B).
    remote_window: CodingWindow<T>,
    /// Indices of coded symbols that are ready to decode.
    decodable: Vec<usize>,
    /// Number of coded symbols successfully decoded.
    decoded_count: usize,
}

impl<T: Symbol> Decoder<T> {
    pub fn new() -> Self {
        Self {
            coded_symbols: Vec::new(),
            window: CodingWindow::new(),
            local_window: CodingWindow::new(),
            remote_window: CodingWindow::new(),
            decodable: Vec::new(),
            decoded_count: 0,
        }
    }

    /// Add a symbol from the decoder's local set.
    ///
    /// Must be called before any [`add_coded_symbol`](Self::add_coded_symbol).
    pub fn add_symbol(&mut self, s: T) {
        self.add_hashed_symbol(HashedSymbol::new(s));
    }

    /// Add a pre-hashed symbol from the decoder's local set.
    pub fn add_hashed_symbol(&mut self, s: HashedSymbol<T>) {
        self.window.add_hashed_symbol(s);
    }

    /// Receive a coded symbol from the encoder.
    ///
    /// The coded symbol is peeled against the known windows (local set,
    /// discovered local-only, discovered remote-only) before being stored.
    pub fn add_coded_symbol(&mut self, mut c: CodedSymbol<T>) {
        // Peel off known symbols from all three windows
        self.window.apply_window(&mut c, -1); // remove local set contribution
        self.remote_window.apply_window(&mut c, -1); // remove already-discovered remote symbols
        self.local_window.apply_window(&mut c, 1); // add back already-discovered local symbols

        // Check if immediately decodable
        if c.is_pure() || c.is_zero() {
            self.decodable.push(self.coded_symbols.len());
        }

        self.coded_symbols.push(c);
    }

    /// Attempt to decode all currently decodable coded symbols via cascading peeling.
    ///
    /// Each pure coded symbol reveals a source symbol, which is then peeled from
    /// all other coded symbols, potentially making more of them decodable.
    pub fn try_decode(&mut self) {
        let mut didx = 0;
        while didx < self.decodable.len() {
            let cidx = self.decodable[didx];
            let c = &self.coded_symbols[cidx];

            match c.count {
                1 => {
                    // Symbol exclusive to the encoder's set (remote)
                    let ns = HashedSymbol {
                        symbol: T::default().xor(&c.symbol),
                        hash: c.hash,
                    };

                    let mapping = CodingWindow::apply_new_symbol(
                        &ns,
                        &mut self.coded_symbols,
                        -1,
                        &mut self.decodable,
                    );
                    self.remote_window
                        .add_hashed_symbol_with_mapping(ns, mapping);
                    self.decoded_count += 1;
                }
                -1 => {
                    // Symbol exclusive to the decoder's set (local)
                    let ns = HashedSymbol {
                        symbol: T::default().xor(&c.symbol),
                        hash: c.hash,
                    };

                    let mapping = CodingWindow::apply_new_symbol(
                        &ns,
                        &mut self.coded_symbols,
                        1,
                        &mut self.decodable,
                    );
                    self.local_window
                        .add_hashed_symbol_with_mapping(ns, mapping);
                    self.decoded_count += 1;
                }
                0 => {
                    // Empty — symbols cancelled out
                    self.decoded_count += 1;
                }
                _ => {}
            }

            didx += 1;
        }
        self.decodable.clear();
    }

    /// Returns `true` if all received coded symbols have been successfully decoded.
    pub fn decoded(&self) -> bool {
        self.decoded_count == self.coded_symbols.len()
    }

    /// Symbols exclusive to the decoder's local set (B \ A).
    pub fn local(&self) -> &[HashedSymbol<T>] {
        self.local_window.symbols()
    }

    /// Symbols exclusive to the encoder's remote set (A \ B).
    pub fn remote(&self) -> &[HashedSymbol<T>] {
        self.remote_window.symbols()
    }

    /// Reset the decoder, clearing all state.
    pub fn reset(&mut self) {
        self.coded_symbols.clear();
        self.window.reset();
        self.local_window.reset();
        self.remote_window.reset();
        self.decodable.clear();
        self.decoded_count = 0;
    }
}

impl<T: Symbol> Default for Decoder<T> {
    fn default() -> Self {
        Self::new()
    }
}
