use alloy::primitives::Address;
// criterion
use criterion::{Criterion, criterion_group, criterion_main};
use dashmap::DashMap;

pub fn criterion_benchmark(c: &mut Criterion) {
    let counter: DashMap<Address, (u64, u64)> = DashMap::new();

    (0..1_000_000).into_iter().for_each(|i| {
        let mut addr = Address::new([0; 20]);
        addr.0.randomize();
        counter.insert(addr, (i, i));
    });

    c.bench_function("alter_all", |b| {
        b.iter(|| counter.alter_all(|_, v| (v.0, 0)))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(25);
    // config = Criterion::default();
    targets = criterion_benchmark
}
criterion_main!(benches);
