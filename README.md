# riblt-rs

A Rust implementation of **Rateless Invertible Bloom Lookup Tables (RIBLT)** for efficient set reconciliation.

Based on the paper ["Practical Rateless Set Reconciliation"](https://arxiv.org/abs/2402.02668) by Lei Yang, Yossi Gilad, and Mohammad Alizadeh, and ported from the [reference Go implementation](https://github.com/yangl1996/riblt).

## What is RIBLT?

RIBLT solves the **set reconciliation problem**: two parties (Alice and Bob) each hold a set of elements and want to efficiently determine which elements are exclusive to each set (the symmetric difference), without transmitting the full sets.

Key properties:

- **Rateless**: Generates an unlimited stream of coded symbols on demand — no need to estimate the difference size in advance
- **Efficient**: Requires approximately **1.35x** the symmetric difference size in coded symbols for successful decoding
- **Communication-optimal**: Overhead is proportional to the difference, not the set sizes

## CLI Tool

The `riblt` binary reads line-delimited data, encodes it into `.riblt` files, and supports comparing or diffing two files.

### Build from stdin

Pipe line-delimited records into `riblt` to produce an encoded file:

```sh
cat records.txt | riblt --out records.riblt
```

Each non-empty line becomes one set element. By default, the number of coded symbols is 2x the input record count (minimum 100). Override with `--num`:

```sh
seq 1 10000 | riblt --out large.riblt --num 5000
```

### Compare two files

Check whether two `.riblt` files represent the same set:

```sh
riblt compare alice.riblt bob.riblt
```

Output:

```
MATCH: sets are identical
  File A: alice.riblt (100 records, 200 symbols)
  File B: bob.riblt (100 records, 200 symbols)
```

Or when sets differ:

```
DIFFER: 2 element(s) differ
  1 only in alice.riblt
  1 only in bob.riblt
```

### Compute the difference

Show which elements are exclusive to each file:

```sh
riblt difference alice.riblt bob.riblt
```

Output:

```
- dave
+ eve
```

Lines prefixed with `-` are in the first file only. Lines prefixed with `+` are in the second file only.

If the encoded files don't contain enough coded symbols to fully decode the difference, `riblt` prints a warning to stderr and exits with code 2.

### Full usage

```
<data> | riblt --out <file.riblt> [--num <count>]
riblt compare <file_a.riblt> <file_b.riblt>
riblt difference <file_a.riblt> <file_b.riblt>
```

## Peer-to-Peer Demo

The `rateless-peer` binary demonstrates live, interactive set reconciliation between two peers over TCP.

```sh
# Terminal 1: start a peer with an initial set
seq 100 200 | rateless-peer

# Terminal 2: connect and reconcile
seq 98 198 | rateless-peer 127.0.0.1:32000
```

Both peers stream coded symbols bidirectionally until the symmetric difference is resolved. After the initial piped input, you can type new values interactively to trigger re-reconciliation.

### Options

Options are passed as query string parameters on the address argument:

```sh
# Keyed hashing (both peers must use the same key)
seq 100 200 | rateless-peer '?key=mysecret'
seq 98 198 | rateless-peer '127.0.0.1:32000?key=mysecret'

# ECMH mode with ristretto255 curve-point checksums (requires --features ecmh)
seq 100 200 | rateless-peer '?ecmh=true'
seq 98 198 | rateless-peer '127.0.0.1:32000?ecmh=true'

# Both options combined
seq 100 200 | rateless-peer '?ecmh=true&key=mysecret'
seq 98 198 | rateless-peer '127.0.0.1:32000?ecmh=true&key=mysecret'
```

The default listen port is 32000. Both peers must use the same options.

## Library Usage

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
