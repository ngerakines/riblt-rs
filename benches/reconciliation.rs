use criterion::{Criterion, criterion_group, criterion_main};
use riblt::{Decoder, Encoder, Symbol};

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
struct BenchSymbol(u64);

impl Symbol for BenchSymbol {
    fn xor(&self, other: &Self) -> Self {
        BenchSymbol(self.0 ^ other.0)
    }

    fn hash(&self) -> u64 {
        let mut h = self.0;
        h ^= h >> 30;
        h = h.wrapping_mul(0xbf58476d1ce4e5b9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94d049bb133111eb);
        h ^= h >> 31;
        h
    }
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for n in [100, 1000, 10000] {
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| {
                let mut enc = Encoder::new();
                for v in 0..n as u64 {
                    enc.add_symbol(BenchSymbol(v));
                }
                for _ in 0..200 {
                    enc.produce_next_coded_symbol();
                }
            });
        });
    }
    group.finish();
}

fn bench_reconcile(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconcile");
    for diff_size in [10, 100, 1000] {
        group.bench_function(format!("d={diff_size}"), |b| {
            b.iter(|| {
                let common_size = 1000u64;
                let mut enc = Encoder::new();
                for v in 0..common_size {
                    enc.add_symbol(BenchSymbol(v));
                }
                for v in common_size..common_size + diff_size as u64 {
                    enc.add_symbol(BenchSymbol(v));
                }

                let mut dec = Decoder::new();
                for v in 0..common_size {
                    dec.add_symbol(BenchSymbol(v));
                }
                for v in (common_size + diff_size as u64)..(common_size + 2 * diff_size as u64) {
                    dec.add_symbol(BenchSymbol(v));
                }

                let max = diff_size * 3;
                for _ in 0..max {
                    let coded = enc.produce_next_coded_symbol();
                    dec.add_coded_symbol(coded);
                    dec.try_decode();
                    if dec.decoded() {
                        break;
                    }
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_reconcile);
criterion_main!(benches);
