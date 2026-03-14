use std::collections::HashSet;

use riblt::{Decoder, Encoder, Sketch, Symbol};

/// A simple test symbol wrapping a u64.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
struct TestSymbol(u64);

impl Symbol for TestSymbol {
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
