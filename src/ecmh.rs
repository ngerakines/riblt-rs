//! ECMH (Elliptic Curve Multiset Hash) support using ristretto255.
//!
//! This module provides [`EcmhChecksum`] and [`EcmhByteSymbol`] for RIBLT set
//! reconciliation with cryptographic integrity guarantees. The 0th coded symbol
//! serves as a cryptographic commitment to the entire set.
//!
//! Enable with the `ecmh` cargo feature.

use std::hash::{DefaultHasher, Hash, Hasher};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use sha2::Sha512;
use siphasher::sip::SipHasher24;

use crate::Symbol;
use crate::symbol::{ChecksumHash, HashKey};

/// A checksum based on a ristretto255 curve point.
///
/// Checksums are combined via point addition (instead of XOR for `u64`).
/// The identity element is the curve's neutral point.
#[derive(Clone, Debug)]
pub struct EcmhChecksum(pub RistrettoPoint);

impl Default for EcmhChecksum {
    fn default() -> Self {
        Self(RistrettoPoint::identity())
    }
}

impl PartialEq for EcmhChecksum {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl ChecksumHash for EcmhChecksum {
    fn combine(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    fn uncombine(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }

    fn negate(&self) -> Self {
        Self(-self.0)
    }

    fn is_zero(&self) -> bool {
        self.0 == RistrettoPoint::identity()
    }
}

/// A variable-length byte string symbol with ECMH checksums.
///
/// XOR pads the shorter operand with zeros (same as [`ByteSymbol`](crate::byte_symbol::ByteSymbol)).
/// The checksum is a ristretto255 point derived via hash-to-curve.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EcmhByteSymbol(pub Vec<u8>);

impl Symbol for EcmhByteSymbol {
    type Checksum = EcmhChecksum;

    fn xor(&self, other: &Self) -> Self {
        let len = self.0.len().max(other.0.len());
        let mut result = vec![0u8; len];
        for (i, b) in self.0.iter().enumerate() {
            result[i] ^= b;
        }
        for (i, b) in other.0.iter().enumerate() {
            result[i] ^= b;
        }
        // Trim trailing zeros to keep canonical form
        while result.last() == Some(&0) {
            result.pop();
        }
        EcmhByteSymbol(result)
    }

    fn hash(&self) -> EcmhChecksum {
        EcmhChecksum(RistrettoPoint::hash_from_bytes::<Sha512>(&self.0))
    }

    fn mapping_seed(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }

    fn keyed_hash(&self, key: &HashKey) -> EcmhChecksum {
        // Incorporate the key into the hash-to-curve input
        let mut input = Vec::with_capacity(key.len() + self.0.len());
        input.extend_from_slice(key);
        input.extend_from_slice(&self.0);
        EcmhChecksum(RistrettoPoint::hash_from_bytes::<Sha512>(&input))
    }

    fn keyed_mapping_seed(&self, key: &HashKey) -> u64 {
        let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}
