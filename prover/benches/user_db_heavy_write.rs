use alloy::primitives::Address;
use std::hint::black_box;
// criterion
use criterion::{
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
    // black_box
};
use dashmap::DashMap;
use rand::Rng;
use scc::HashMap;

pub fn criterion_benchmark(c: &mut Criterion) {
    let size = 1_250_000;
    let mut rng = rand::thread_rng();
    let d_1m: DashMap<Address, (u64, u64)> = DashMap::with_capacity(size as usize);
    let scc_1m: HashMap<Address, (u64, u64)> = HashMap::with_capacity(size as usize);

    (0..size).into_iter().for_each(|_i| {
        let mut addr = Address::new([0; 20]);
        addr.0.randomize();
        let n1 = rng.r#gen();
        let n2 = rng.r#gen();
        d_1m.insert(addr, (n1, n2));
        scc_1m.insert(addr, (n1, n2)).unwrap();
    });

    let mut group = c.benchmark_group("Scc versus DashMap alter_all");

    group.throughput(Throughput::Elements(size));
    group.bench_function(BenchmarkId::new("Dashmap", size), |b| {
        b.iter(|| {
            black_box(d_1m.alter_all(|_, v| black_box((v.0, 0))));
        })
    });

    group.bench_function(BenchmarkId::new("Scc", size), |b| {
        b.iter(|| {
            black_box(scc_1m.retain(|_, v| {
                black_box(*v = (v.0, 0));
                black_box(true)
            }));
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(45))
        .sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(benches);
