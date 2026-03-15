//! # riblt
//!
//! Rateless Invertible Bloom Lookup Tables for efficient set reconciliation.
//!
//! RIBLT allows two parties holding sets A and B to compute their symmetric difference
//! (A \ B and B \ A) with communication proportional only to the difference size.
//! The "rateless" property means coded symbols are generated on demand — no need to
//! estimate the difference size in advance. Approximately 1.35x the difference size
//! in coded symbols suffices for successful decoding.
//!
//! ## Quick Start
//!
//! ```rust
//! use riblt::{Encoder, Decoder, Symbol};
//!
//! // Define your symbol type
//! #[derive(Clone, Default, Debug, PartialEq)]
//! struct Item(u64);
//!
//! impl Symbol for Item {
//!     fn xor(&self, other: &Self) -> Self {
//!         Item(self.0 ^ other.0)
//!     }
//!     fn hash(&self) -> u64 {
//!         // Non-homomorphic hash (e.g., splitmix64)
//!         let mut h = self.0;
//!         h ^= h >> 30; h = h.wrapping_mul(0xbf58476d1ce4e5b9);
//!         h ^= h >> 27; h = h.wrapping_mul(0x94d049bb133111eb);
//!         h ^= h >> 31; h
//!     }
//! }
//!
//! // Alice has {1, 2, 3, 4}, Bob has {1, 2, 3, 5}
//! let mut encoder = Encoder::new();
//! for &v in &[1u64, 2, 3, 4] {
//!     encoder.add_symbol(Item(v));
//! }
//!
//! let mut decoder = Decoder::new();
//! for &v in &[1u64, 2, 3, 5] {
//!     decoder.add_symbol(Item(v));
//! }
//!
//! // Stream coded symbols until decoded
//! for _ in 0..50 {
//!     let coded = encoder.produce_next_coded_symbol();
//!     decoder.add_coded_symbol(coded);
//!     decoder.try_decode();
//!     if decoder.decoded() {
//!         break;
//!     }
//! }
//!
//! assert!(decoder.decoded());
//! // remote = symbols only in Alice's set (Item(4))
//! // local  = symbols only in Bob's set  (Item(5))
//! assert_eq!(decoder.remote().len(), 1);
//! assert_eq!(decoder.local().len(), 1);
//! ```

pub mod byte_symbol;
mod coded_symbol;
mod decoder;
mod encoder;
pub mod file_format;
mod mapping;
mod sketch;
mod symbol;
mod window;

pub use coded_symbol::CodedSymbol;
pub use decoder::Decoder;
pub use encoder::Encoder;
pub use mapping::RandomMapping;
pub use sketch::Sketch;
pub use symbol::{HashKey, HashedSymbol, Symbol};
