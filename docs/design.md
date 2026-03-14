# Implementation Design

This document describes the design decisions and architecture of the `riblt` Rust crate.

## Reference Implementations

This implementation is ported from three sources:

1. **Go** ([yangl1996/riblt](https://github.com/yangl1996/riblt)) — canonical reference by the paper authors
2. **Rust** ([samWighton/rateless_iblt](https://github.com/samWighton/rateless_iblt)) — community port
3. **C++** ([hoytech/riblet](https://github.com/hoytech/riblet)) — CLI tool with binary format

The Go implementation is followed most closely as it is the canonical reference from the paper authors.

## Module Architecture

```
lib.rs              ← public re-exports
├── symbol.rs       ← Symbol trait + HashedSymbol
├── coded_symbol.rs ← CodedSymbol (XOR-combined output)
├── mapping.rs      ← RandomMapping (PRNG-based index generator)
├── window.rs       ← CodingWindow (internal min-heap + mapping tracker)
├── encoder.rs      ← Encoder (wraps CodingWindow for generating coded symbols)
├── decoder.rs      ← Decoder (reconciliation state machine)
└── sketch.rs       ← Sketch (fixed-size batch IBLT)
```

## Data Flow

```
Encoder                                    Decoder
┌─────────────┐                           ┌─────────────────┐
│ add_symbol() │                           │ add_symbol()    │
│ (set A)      │                           │ (set B)         │
└──────┬──────┘                           └────────┬────────┘
       │                                           │
       ▼                                           ▼
┌──────────────────┐   CodedSymbol    ┌──────────────────────┐
│ produce_next_    │ ───────────────► │ add_coded_symbol()   │
│ coded_symbol()   │                  │ try_decode()         │
└──────────────────┘                  └──────────┬───────────┘
                                                 │
                                      ┌──────────▼───────────┐
                                      │ decoded() → true     │
                                      │ local()  → B \ A     │
                                      │ remote() → A \ B     │
                                      └──────────────────────┘
```

## Key Design Decisions

### 1. Generic Symbol Trait

Users implement `Symbol` for their own types. This avoids coupling to any specific hash function or data representation. The trait requires:
- `xor(&self, &Self) -> Self` — group operation
- `hash(&self) -> u64` — non-homomorphic hash

### 2. Custom Min-Heap (MappingHeap)

Rather than using `std::collections::BinaryHeap`, we implement a custom min-heap mirroring the Go implementation's `mappingHeap`. This allows in-place modification of the root element followed by `fix_head()`, which is more efficient than pop+push for the sliding window pattern.

### 3. Separate Mapping Storage

The `CodingWindow` stores `RandomMapping` instances in a parallel `Vec` alongside symbols, indexed by source index. This mirrors the Go implementation and allows the heap entries to remain lightweight (just two `usize` fields).

### 4. No External Dependencies for Core

The core library has zero dependencies. Hash functions are the user's responsibility via the `Symbol` trait. This keeps the crate minimal and flexible.

### 5. Saturating Arithmetic in RandomMapping

The random mapping uses `saturating_add` for index computation to handle the case where indices grow beyond `usize::MAX`. In practice, indices that exceed the coded symbol count are simply skipped, so saturation is safe.

## Comparison with Go Implementation

| Aspect | Go | Rust |
|--------|----|----|
| Symbol interface | Generic type parameter with `XOR`/`Hash` methods | `Symbol` trait with `xor`/`hash` methods |
| Coded symbol | Value type, returned by copy | Passed by mutable reference |
| Heap | Custom `mappingHeap` with `fixHead`/`fixTail` | Custom `MappingHeap` mirroring Go's approach |
| Direction constants | `add = 1`, `remove = -1` | Literal `1` and `-1` as `i64` |
| Encoder/Decoder | Type alias to `codingWindow` | Wraps `CodingWindow` |
