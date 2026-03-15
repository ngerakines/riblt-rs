use crate::coded_symbol::CodedSymbol;
use crate::mapping::RandomMapping;
use crate::symbol::{HashKey, HashedSymbol, Symbol};

/// Entry in the priority queue mapping a source symbol to its next coded symbol index.
#[derive(Debug, Clone)]
struct SymbolMapping {
    source_idx: usize,
    coded_idx: usize,
}

/// Min-heap of `SymbolMapping` ordered by `coded_idx`.
///
/// Mirrors the Go implementation's `mappingHeap` with `fixHead` and `fixTail`.
#[derive(Debug, Clone)]
struct MappingHeap {
    entries: Vec<SymbolMapping>,
}

impl MappingHeap {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn peek(&self) -> Option<&SymbolMapping> {
        self.entries.first()
    }

    fn push(&mut self, entry: SymbolMapping) {
        self.entries.push(entry);
        self.fix_tail();
    }

    /// Re-establish heap invariant after modifying the first (root) element.
    fn fix_head(&mut self) {
        let mut curr = 0;
        loop {
            let child = curr * 2 + 1;
            if child >= self.entries.len() {
                break;
            }
            let rc = child + 1;
            let min_child = if rc < self.entries.len()
                && self.entries[rc].coded_idx < self.entries[child].coded_idx
            {
                rc
            } else {
                child
            };
            if self.entries[curr].coded_idx <= self.entries[min_child].coded_idx {
                break;
            }
            self.entries.swap(curr, min_child);
            curr = min_child;
        }
    }

    /// Re-establish heap invariant after inserting at the tail.
    fn fix_tail(&mut self) {
        let mut curr = self.entries.len() - 1;
        loop {
            if curr == 0 {
                break;
            }
            let parent = (curr - 1) / 2;
            if self.entries[parent].coded_idx <= self.entries[curr].coded_idx {
                break;
            }
            self.entries.swap(parent, curr);
            curr = parent;
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Internal sliding window tracking which source symbols map to each coded symbol index.
///
/// Mirrors the Go `codingWindow` type. Stores source symbols alongside their
/// random mapping generators and a min-heap for efficient lookup of which
/// symbols map to the current coded index.
#[derive(Debug, Clone)]
pub(crate) struct CodingWindow<T: Symbol> {
    symbols: Vec<HashedSymbol<T>>,
    mappings: Vec<RandomMapping>,
    queue: MappingHeap,
    next_idx: usize,
}

impl<T: Symbol> CodingWindow<T> {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            mappings: Vec::new(),
            queue: MappingHeap::new(),
            next_idx: 0,
        }
    }

    /// Add a symbol with a fresh mapping (seeded from its mapping seed, starting at index 0).
    pub fn add_hashed_symbol(&mut self, s: HashedSymbol<T>) {
        let m = RandomMapping::new(s.mapping_seed);
        self.add_hashed_symbol_with_mapping(s, m);
    }

    /// Add a symbol with an existing mapping state.
    pub fn add_hashed_symbol_with_mapping(&mut self, s: HashedSymbol<T>, m: RandomMapping) {
        let source_idx = self.symbols.len();
        let coded_idx = m.last_index();
        self.symbols.push(s);
        self.mappings.push(m);
        self.queue.push(SymbolMapping {
            source_idx,
            coded_idx,
        });
    }

    /// Apply all source symbols that map to the current coded index, then advance.
    pub fn apply_window(&mut self, coded: &mut CodedSymbol<T>, direction: i64) {
        if !self.queue.is_empty() {
            while let Some(top) = self.queue.peek() {
                if top.coded_idx != self.next_idx {
                    break;
                }
                let src_idx = top.source_idx;
                coded.apply(&self.symbols[src_idx], direction);
                // Advance this symbol's mapping to its next coded index
                let next_coded = self.mappings[src_idx].next_index();
                self.queue.entries[0].coded_idx = next_coded;
                self.queue.fix_head();
            }
        }
        self.next_idx += 1;
    }

    /// Apply a newly discovered symbol to all coded symbols it maps to.
    ///
    /// Starts from index 0 and walks through all existing coded symbols.
    /// Returns the mapping state for continued tracking.
    pub fn apply_new_symbol(
        s: &HashedSymbol<T>,
        coded_symbols: &mut [CodedSymbol<T>],
        direction: i64,
        decodable: &mut Vec<usize>,
        key: Option<&HashKey>,
    ) -> RandomMapping {
        let mut m = RandomMapping::new(s.mapping_seed);
        let num_coded = coded_symbols.len();

        // First mapped index is always 0 (from RandomMapping::new)
        while m.last_index() < num_coded {
            let cidx = m.last_index();
            coded_symbols[cidx].apply(s, direction);

            // Check if newly decodable (only count ±1, not 0 — see Go comment about duplicates)
            if coded_symbols[cidx].is_pure_with_key(key) {
                decodable.push(cidx);
            }

            m.next_index();
        }

        m
    }

    /// Returns the symbols stored in this window.
    pub fn symbols(&self) -> &[HashedSymbol<T>] {
        &self.symbols
    }

    /// Reset the window to its initial state.
    pub fn reset(&mut self) {
        self.symbols.clear();
        self.mappings.clear();
        self.queue.clear();
        self.next_idx = 0;
    }
}
