# riblt-rs

A Rust implementation of **Rateless Invertible Bloom Lookup Tables (RIBLT)** for efficient set reconciliation.

Based on the paper ["Practical Rateless Set Reconciliation"](https://arxiv.org/abs/2402.02668) by Lei Yang, Yossi Gilad, and Mohammad Alizadeh, and ported from the [reference Go implementation](https://github.com/yangl1996/riblt).

## What is RIBLT?

RIBLT solves the **set reconciliation problem**: two parties (Alice and Bob) each hold a set of elements and want to efficiently determine which elements are exclusive to each set (the symmetric difference), without transmitting the full sets.

Key properties:

- **Rateless**: Generates an unlimited stream of coded symbols on demand — no need to estimate the difference size in advance
- **Efficient**: Requires approximately **1.35x** the symmetric difference size in coded symbols for successful decoding
- **Communication-optimal**: Overhead is proportional to the difference, not the set sizes

## Usage

```rust
use riblt::{Encoder, Decoder, Symbol};

// Define your symbol type
#[derive(Clone, Default, Debug, PartialEq)]
struct Item(u64);

impl Symbol for Item {
    fn xor(&self, other: &Self) -> Self {
        Item(self.0 ^ other.0)
    }
    fn hash(&self) -> u64 {
        let mut h = self.0;
        h ^= h >> 30; h = h.wrapping_mul(0xbf58476d1ce4e5b9);
        h ^= h >> 27; h = h.wrapping_mul(0x94d049bb133111eb);
        h ^= h >> 31; h
    }
}

// Alice has {1, 2, 3, 4}, Bob has {1, 2, 3, 5}
let mut encoder = Encoder::new();
for &v in &[1u64, 2, 3, 4] {
    encoder.add_symbol(Item(v));
}

let mut decoder = Decoder::new();
for &v in &[1u64, 2, 3, 5] {
    decoder.add_symbol(Item(v));
}

// Stream coded symbols until decoded
for _ in 0..50 {
    let coded = encoder.produce_next_coded_symbol();
    decoder.add_coded_symbol(coded);
    decoder.try_decode();
    if decoder.decoded() {
        break;
    }
}

assert!(decoder.decoded());
// remote = elements only in Alice's set: {4}
// local  = elements only in Bob's set:   {5}
```

## The Symbol Trait

To use RIBLT with your own types, implement the `Symbol` trait:

```rust
pub trait Symbol: Clone + Default {
    /// XOR group operation. Must be associative, have identity (Default), and be self-inverse.
    fn xor(&self, other: &Self) -> Self;

    /// Non-homomorphic hash. Must NOT satisfy: hash(a ^ b) == hash(a) ^ hash(b).
    fn hash(&self) -> u64;
}
```

The `xor` operation must form a group (associative, identity via `Default`, self-inverse). The `hash` function must be **non-homomorphic** with respect to XOR — this is critical for correctness during decoding.

## API Overview

| Type | Purpose |
|------|---------|
| `Encoder<T>` | Generates an infinite stream of coded symbols for a set |
| `Decoder<T>` | Receives coded symbols and recovers the symmetric difference |
| `Sketch<T>` | Fixed-size batch IBLT for standalone use |
| `CodedSymbol<T>` | A single coded symbol (XOR of mapped source symbols) |
| `HashedSymbol<T>` | A symbol paired with its pre-computed hash |
| `RandomMapping` | Deterministic pseudo-random index generator |

## License

MIT
