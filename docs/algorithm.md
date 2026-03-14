# RIBLT Algorithm Summary

This document summarizes the Rateless Invertible Bloom Lookup Table (RIBLT) algorithm as described in ["Practical Rateless Set Reconciliation"](https://arxiv.org/abs/2402.02668) by Yang, Gilad, and Alizadeh.

## Problem Statement

Two parties (Alice and Bob) hold sets A and B of fixed-length elements. They want to compute the symmetric difference A △ B = (A \ B) ∪ (B \ A) with communication proportional to |A △ B| = d, not to the set sizes.

## Foundation: Invertible Bloom Lookup Tables (IBLT)

An IBLT is an array of cells, each containing three fields:
- **symbol**: XOR of all element values mapped to this cell
- **hash**: XOR of all element hashes mapped to this cell
- **count**: number of elements mapped to this cell

Elements are inserted using k hash functions. The XOR group operation enables subtraction: given IBLT(A) and IBLT(B), their cell-wise difference yields IBLT(A △ B).

**Decoding** works by "peeling": find a cell with count = ±1 where the hash matches the symbol's hash (a "pure" cell), recover that element, remove it from all cells it maps to, and repeat. This cascading process recovers all elements if the IBLT is large enough relative to d.

## The Rateless Extension

The key innovation: instead of a fixed-size IBLT, generate an **infinite sequence** of coded symbols. Each coded symbol is the XOR-combination of a pseudo-random subset of source symbols.

The subset is determined by a **random mapping**: each source symbol uses a deterministic PRNG (seeded by its hash) to generate an infinite sequence of coded symbol indices it maps to. The probability of mapping to index i decreases as roughly 1/(1+i/2).

### Random Mapping Formula

```
prng *= 0xda942042e4dd58b5          // LCG step
gap = ceil((lastIndex + 1.5) * (2^32 / sqrt(prng + 1) - 1))
lastIndex += gap
```

This ensures:
- Early coded symbols have high degree (many source symbols)
- Later coded symbols have low degree
- The distribution enables efficient peeling with ~1.35d coded symbols

## Protocol Flow

### Encoding (Alice)
1. Add all source symbols from set A to the encoder
2. Generate coded symbols one at a time: for each, XOR together all source symbols whose random mapping includes that coded index
3. Stream coded symbols to Bob

### Decoding (Bob)
1. Add all local symbols from set B to the decoder
2. For each received coded symbol:
   a. Peel off contributions from known symbols (local set B, discovered local-only, discovered remote-only)
   b. Check if the result is "pure" (count ±1 with matching hash) or "zero" (count 0, hash 0)
   c. If pure, recover the source symbol and cascade: peel it from all other coded symbols
3. Continue until all coded symbols are resolved

### Decoding Details

When a coded symbol has count = 1, it contains a symbol exclusive to Alice's set (remote). When count = -1, it contains a symbol exclusive to Bob's set (local). When count = 0 with hash = 0, it's fully resolved (all contributions cancelled).

The cascading peeling process can trigger chain reactions: resolving one symbol may make others resolvable.

## Performance

- **Communication**: ~1.35d coded symbols suffice for d = |A △ B|
- **Encoding time**: O(n log d) where n = |A| (using a priority queue)
- **Decoding time**: O(d log d)
- **No pre-estimation**: Unlike fixed IBLTs, no need to guess d in advance
- The overhead ratio 1.35 holds for large d; for small d it may be slightly higher

## Key Requirements

1. The XOR operation must form a group (associative, identity, self-inverse)
2. The hash function must be **non-homomorphic**: hash(a ⊕ b) ≠ hash(a) ⊕ hash(b) with high probability
3. Coded symbols must be processed in the exact order they are generated
