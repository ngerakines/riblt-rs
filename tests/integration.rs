use std::collections::HashSet;

use riblt::{Decoder, Encoder, HashKey, Sketch, Symbol};

/// A simple test symbol wrapping a u64.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
struct TestSymbol(u64);

impl Symbol for TestSymbol {
    type Checksum = u64;

    fn xor(&self, other: &Self) -> Self {
        TestSymbol(self.0 ^ other.0)
    }

    fn hash(&self) -> u64 {
        // splitmix64 — non-homomorphic
        let mut h = self.0;
        h ^= h >> 30;
        h = h.wrapping_mul(0xbf58476d1ce4e5b9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94d049bb133111eb);
        h ^= h >> 31;
        h
    }

    fn mapping_seed(&self) -> u64 {
        self.hash()
    }

    fn keyed_hash(&self, key: &HashKey) -> u64 {
        use siphasher::sip::SipHasher24;
        use std::hash::{Hash, Hasher};
        let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        self.0.hash(&mut hasher);
        hasher.finish()
    }

    fn keyed_mapping_seed(&self, key: &HashKey) -> u64 {
        self.keyed_hash(key)
    }
}

/// Run a full reconciliation and verify the symmetric difference.
fn reconcile(alice_set: &[u64], bob_set: &[u64], max_symbols: usize) {
    let mut encoder = Encoder::new();
    for &v in alice_set {
        encoder.add_symbol(TestSymbol(v));
    }

    let mut decoder = Decoder::new();
    for &v in bob_set {
        decoder.add_symbol(TestSymbol(v));
    }

    for _ in 0..max_symbols {
        let coded = encoder.produce_next_coded_symbol();
        decoder.add_coded_symbol(coded);
        decoder.try_decode();
        if decoder.decoded() {
            break;
        }
    }

    assert!(
        decoder.decoded(),
        "failed to decode within {max_symbols} symbols"
    );

    // Verify symmetric difference
    let alice: HashSet<u64> = alice_set.iter().copied().collect();
    let bob: HashSet<u64> = bob_set.iter().copied().collect();

    let expected_remote: HashSet<u64> = alice.difference(&bob).copied().collect();
    let expected_local: HashSet<u64> = bob.difference(&alice).copied().collect();

    let actual_remote: HashSet<u64> = decoder.remote().iter().map(|s| s.symbol.0).collect();
    let actual_local: HashSet<u64> = decoder.local().iter().map(|s| s.symbol.0).collect();

    assert_eq!(actual_remote, expected_remote, "remote mismatch");
    assert_eq!(actual_local, expected_local, "local mismatch");
}

#[test]
fn basic_reconciliation() {
    reconcile(&[1, 2, 3, 4], &[1, 2, 3, 5], 50);
}

#[test]
fn identical_sets() {
    reconcile(&[10, 20, 30], &[10, 20, 30], 50);
}

#[test]
fn empty_sets() {
    reconcile(&[], &[], 10);
}

#[test]
fn one_empty_set() {
    reconcile(&[1, 2, 3], &[], 50);
    reconcile(&[], &[4, 5, 6], 50);
}

#[test]
fn disjoint_sets() {
    reconcile(&[1, 2, 3], &[4, 5, 6], 100);
}

#[test]
fn one_sided_difference() {
    // Alice has a superset of Bob
    reconcile(&[1, 2, 3, 4, 5], &[1, 2, 3], 50);
    // Bob has a superset of Alice
    reconcile(&[1, 2, 3], &[1, 2, 3, 4, 5], 50);
}

#[test]
fn larger_difference() {
    let common: Vec<u64> = (1..=100).collect();
    let alice_only: Vec<u64> = (1000..1020).collect();
    let bob_only: Vec<u64> = (2000..2015).collect();

    let alice: Vec<u64> = common.iter().chain(alice_only.iter()).copied().collect();
    let bob: Vec<u64> = common.iter().chain(bob_only.iter()).copied().collect();

    // d = 35, need ~47 coded symbols (1.35 * 35)
    reconcile(&alice, &bob, 200);
}

#[test]
fn stress_test() {
    let common: Vec<u64> = (1..=1000).collect();
    let alice_only: Vec<u64> = (10000..10100).collect();
    let bob_only: Vec<u64> = (20000..20100).collect();

    let alice: Vec<u64> = common.iter().chain(alice_only.iter()).copied().collect();
    let bob: Vec<u64> = common.iter().chain(bob_only.iter()).copied().collect();

    // d = 200, need ~270 coded symbols
    reconcile(&alice, &bob, 1000);
}

#[test]
fn deterministic_encoding() {
    let mut enc1 = Encoder::new();
    let mut enc2 = Encoder::new();
    for v in 1..=10u64 {
        enc1.add_symbol(TestSymbol(v));
        enc2.add_symbol(TestSymbol(v));
    }

    for _ in 0..20 {
        let c1 = enc1.produce_next_coded_symbol();
        let c2 = enc2.produce_next_coded_symbol();
        assert_eq!(c1.hash, c2.hash);
        assert_eq!(c1.count, c2.count);
        assert_eq!(c1.symbol.0, c2.symbol.0);
    }
}

#[test]
fn sketch_basic() {
    let size = 100;
    let mut sketch_a = Sketch::<TestSymbol>::new(size);
    let mut sketch_b = Sketch::<TestSymbol>::new(size);

    // Common elements
    for v in 1..=50u64 {
        sketch_a.add_symbol(TestSymbol(v));
        sketch_b.add_symbol(TestSymbol(v));
    }
    // Alice-only
    for v in 100..=105u64 {
        sketch_a.add_symbol(TestSymbol(v));
    }
    // Bob-only
    for v in 200..=203u64 {
        sketch_b.add_symbol(TestSymbol(v));
    }

    sketch_a.subtract(&sketch_b);
    let (fwd, rev, success) = sketch_a.decode();

    assert!(success, "sketch decode failed");
    let fwd_set: HashSet<u64> = fwd.iter().map(|s| s.symbol.0).collect();
    let rev_set: HashSet<u64> = rev.iter().map(|s| s.symbol.0).collect();

    let expected_fwd: HashSet<u64> = (100..=105).collect();
    let expected_rev: HashSet<u64> = (200..=203).collect();

    assert_eq!(fwd_set, expected_fwd);
    assert_eq!(rev_set, expected_rev);
}

/// Run a keyed reconciliation and verify the symmetric difference.
fn reconcile_keyed(alice_set: &[u64], bob_set: &[u64], key: HashKey, max_symbols: usize) {
    let mut encoder = Encoder::with_key(key);
    for &v in alice_set {
        encoder.add_symbol(TestSymbol(v));
    }

    let mut decoder = Decoder::with_key(key);
    for &v in bob_set {
        decoder.add_symbol(TestSymbol(v));
    }

    for _ in 0..max_symbols {
        let coded = encoder.produce_next_coded_symbol();
        decoder.add_coded_symbol(coded);
        decoder.try_decode();
        if decoder.decoded() {
            break;
        }
    }

    assert!(
        decoder.decoded(),
        "keyed: failed to decode within {max_symbols} symbols"
    );

    let alice: HashSet<u64> = alice_set.iter().copied().collect();
    let bob: HashSet<u64> = bob_set.iter().copied().collect();

    let expected_remote: HashSet<u64> = alice.difference(&bob).copied().collect();
    let expected_local: HashSet<u64> = bob.difference(&alice).copied().collect();

    let actual_remote: HashSet<u64> = decoder.remote().iter().map(|s| s.symbol.0).collect();
    let actual_local: HashSet<u64> = decoder.local().iter().map(|s| s.symbol.0).collect();

    assert_eq!(actual_remote, expected_remote, "keyed: remote mismatch");
    assert_eq!(actual_local, expected_local, "keyed: local mismatch");
}

#[test]
fn keyed_basic_reconciliation() {
    let key: HashKey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    reconcile_keyed(&[1, 2, 3, 4], &[1, 2, 3, 5], key, 50);
}

#[test]
fn keyed_larger_difference() {
    let key: HashKey = [42; 16];
    let common: Vec<u64> = (1..=100).collect();
    let alice_only: Vec<u64> = (1000..1020).collect();
    let bob_only: Vec<u64> = (2000..2015).collect();

    let alice: Vec<u64> = common.iter().chain(alice_only.iter()).copied().collect();
    let bob: Vec<u64> = common.iter().chain(bob_only.iter()).copied().collect();

    reconcile_keyed(&alice, &bob, key, 200);
}

#[test]
fn keyed_different_keys_produce_different_hashes() {
    let key_a: HashKey = [1; 16];
    let key_b: HashKey = [2; 16];
    let sym = TestSymbol(42);

    assert_ne!(sym.keyed_hash(&key_a), sym.keyed_hash(&key_b));
}

#[test]
fn keyed_deterministic_encoding() {
    let key: HashKey = [7; 16];
    let mut enc1 = Encoder::with_key(key);
    let mut enc2 = Encoder::with_key(key);
    for v in 1..=10u64 {
        enc1.add_symbol(TestSymbol(v));
        enc2.add_symbol(TestSymbol(v));
    }

    for _ in 0..20 {
        let c1 = enc1.produce_next_coded_symbol();
        let c2 = enc2.produce_next_coded_symbol();
        assert_eq!(c1.hash, c2.hash);
        assert_eq!(c1.count, c2.count);
        assert_eq!(c1.symbol.0, c2.symbol.0);
    }
}

// --- ECMH tests ---

#[cfg(feature = "ecmh")]
mod ecmh_tests {
    use std::collections::HashSet;

    use riblt::ecmh::EcmhByteSymbol;
    use riblt::{Decoder, Encoder, HashKey, Sketch};

    fn reconcile_ecmh(alice_set: &[&[u8]], bob_set: &[&[u8]], max_symbols: usize) {
        let mut encoder = Encoder::new();
        for &v in alice_set {
            encoder.add_symbol(EcmhByteSymbol(v.to_vec()));
        }

        let mut decoder = Decoder::new();
        for &v in bob_set {
            decoder.add_symbol(EcmhByteSymbol(v.to_vec()));
        }

        for _ in 0..max_symbols {
            let coded = encoder.produce_next_coded_symbol();
            decoder.add_coded_symbol(coded);
            decoder.try_decode();
            if decoder.decoded() {
                break;
            }
        }

        assert!(
            decoder.decoded(),
            "ecmh: failed to decode within {max_symbols} symbols"
        );

        let alice: HashSet<Vec<u8>> = alice_set.iter().map(|s| s.to_vec()).collect();
        let bob: HashSet<Vec<u8>> = bob_set.iter().map(|s| s.to_vec()).collect();

        let expected_remote: HashSet<Vec<u8>> = alice.difference(&bob).cloned().collect();
        let expected_local: HashSet<Vec<u8>> = bob.difference(&alice).cloned().collect();

        let actual_remote: HashSet<Vec<u8>> = decoder
            .remote()
            .iter()
            .map(|s| s.symbol.0.clone())
            .collect();
        let actual_local: HashSet<Vec<u8>> =
            decoder.local().iter().map(|s| s.symbol.0.clone()).collect();

        assert_eq!(actual_remote, expected_remote, "ecmh: remote mismatch");
        assert_eq!(actual_local, expected_local, "ecmh: local mismatch");
    }

    #[test]
    fn ecmh_basic_reconciliation() {
        reconcile_ecmh(
            &[b"alpha", b"beta", b"gamma", b"delta"],
            &[b"alpha", b"beta", b"gamma", b"epsilon"],
            50,
        );
    }

    #[test]
    fn ecmh_identical_sets() {
        reconcile_ecmh(&[b"a", b"b", b"c"], &[b"a", b"b", b"c"], 50);
    }

    #[test]
    fn ecmh_empty_sets() {
        reconcile_ecmh(&[], &[], 10);
    }

    #[test]
    fn ecmh_disjoint_sets() {
        reconcile_ecmh(&[b"a", b"b", b"c"], &[b"d", b"e", b"f"], 100);
    }

    #[test]
    fn ecmh_larger_difference() {
        let common: Vec<Vec<u8>> = (0..100u32)
            .map(|i| format!("common-{i}").into_bytes())
            .collect();
        let alice_only: Vec<Vec<u8>> = (0..20u32)
            .map(|i| format!("alice-{i}").into_bytes())
            .collect();
        let bob_only: Vec<Vec<u8>> = (0..15u32)
            .map(|i| format!("bob-{i}").into_bytes())
            .collect();

        let alice: Vec<&[u8]> = common
            .iter()
            .chain(alice_only.iter())
            .map(|v| v.as_slice())
            .collect();
        let bob: Vec<&[u8]> = common
            .iter()
            .chain(bob_only.iter())
            .map(|v| v.as_slice())
            .collect();

        reconcile_ecmh(&alice, &bob, 200);
    }

    #[test]
    fn ecmh_sketch_basic() {
        let size = 100;
        let mut sketch_a = Sketch::<EcmhByteSymbol>::new(size);
        let mut sketch_b = Sketch::<EcmhByteSymbol>::new(size);

        // Common elements
        for i in 0..50u32 {
            let s = format!("item-{i}").into_bytes();
            sketch_a.add_symbol(EcmhByteSymbol(s.clone()));
            sketch_b.add_symbol(EcmhByteSymbol(s));
        }
        // A-only
        for i in 100..106u32 {
            sketch_a.add_symbol(EcmhByteSymbol(format!("a-{i}").into_bytes()));
        }
        // B-only
        for i in 200..204u32 {
            sketch_b.add_symbol(EcmhByteSymbol(format!("b-{i}").into_bytes()));
        }

        sketch_a.subtract(&sketch_b);
        let (fwd, rev, success) = sketch_a.decode();

        assert!(success, "ecmh sketch decode failed");
        assert_eq!(fwd.len(), 6);
        assert_eq!(rev.len(), 4);
    }

    #[test]
    fn ecmh_keyed_reconciliation() {
        let key: HashKey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let mut encoder = Encoder::with_key(key);
        for v in &[b"a".as_slice(), b"b", b"c", b"d"] {
            encoder.add_symbol(EcmhByteSymbol(v.to_vec()));
        }

        let mut decoder = Decoder::with_key(key);
        for v in &[b"a".as_slice(), b"b", b"c", b"e"] {
            decoder.add_symbol(EcmhByteSymbol(v.to_vec()));
        }

        for _ in 0..50 {
            let coded = encoder.produce_next_coded_symbol();
            decoder.add_coded_symbol(coded);
            decoder.try_decode();
            if decoder.decoded() {
                break;
            }
        }

        assert!(decoder.decoded(), "ecmh keyed: failed to decode");
        assert_eq!(decoder.remote().len(), 1);
        assert_eq!(decoder.local().len(), 1);
    }

    #[test]
    fn ecmh_identity_element() {
        use riblt::ChecksumHash;
        use riblt::ecmh::EcmhChecksum;

        let zero = EcmhChecksum::default();
        assert!(zero.is_zero());

        let point = EcmhByteSymbol(b"test".to_vec());
        let hash = riblt::Symbol::hash(&point);
        assert!(!hash.is_zero());

        // combine with identity should return same
        let combined = hash.combine(&zero);
        assert_eq!(combined, hash);

        // combine with self should not be zero (not self-inverse like XOR)
        let doubled = hash.combine(&hash);
        assert!(!doubled.is_zero());
    }
}
