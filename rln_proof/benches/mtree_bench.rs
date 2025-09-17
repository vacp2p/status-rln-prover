use std::hint::black_box;
// std
use ark_bn254::Fr;
use std::path::PathBuf;
use std::str::FromStr;
// third-party
use ark_std::{UniformRand, rand::thread_rng};
use rln::{pm_tree_adapter::PmtreeConfig, poseidon_tree::PoseidonTree};
use serde::{Deserialize, Serialize};
use zerokit_utils::ZerokitMerkleTree;
// Criterion
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

#[derive(Serialize, Deserialize)]
struct PmTreeConfigJson {
    path: PathBuf,
    temporary: bool,
    cache_capacity: u64,
    flush_every_ms: u64,
    mode: String,
    use_compression: bool,
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let temp_folder_tree_20 = tempfile::tempdir().unwrap();
    let temp_folder_tree_20_b2 = tempfile::tempdir().unwrap();
    let temp_folder_tree_21 = tempfile::tempdir().unwrap();
    let temp_folder_tree_21_b2 = tempfile::tempdir().unwrap();
    let temp_folder_tree_22 = tempfile::tempdir().unwrap();
    let temp_folder_tree_22_b2 = tempfile::tempdir().unwrap();

    let mut config_ = PmTreeConfigJson {
        path: temp_folder_tree_20.path().to_owned(),
        temporary: false,
        cache_capacity: 100_000,
        flush_every_ms: 12_000,
        mode: "HighThroughput".to_string(),
        use_compression: false,
    };
    let mut tree_d20 = {
        let config_str = serde_json::to_string(&config_).unwrap();
        // Note: in Zerokit 0.8 this is the only way to initialize a PmTreeConfig
        let config = PmtreeConfig::from_str(config_str.as_str()).unwrap();
        PoseidonTree::new(20, Default::default(), config).unwrap()
    };

    let mut tree_d20_b2 = {
        config_.path = temp_folder_tree_20_b2.path().to_owned();
        let config_str = serde_json::to_string(&config_).unwrap();
        // Note: in Zerokit 0.8 this is the only way to initialize a PmTreeConfig
        let config = PmtreeConfig::from_str(config_str.as_str()).unwrap();
        PoseidonTree::new(20, Default::default(), config).unwrap()
    };

    let mut tree_d21 = {
        config_.path = temp_folder_tree_21.path().to_owned();
        let config_str = serde_json::to_string(&config_).unwrap();
        // Note: in Zerokit 0.8 this is the only way to initialize a PmTreeConfig
        let config = PmtreeConfig::from_str(config_str.as_str()).unwrap();
        PoseidonTree::new(21, Default::default(), config).unwrap()
    };

    let mut tree_d21_b2 = {
        config_.path = temp_folder_tree_21_b2.path().to_owned();
        let config_str = serde_json::to_string(&config_).unwrap();
        // Note: in Zerokit 0.8 this is the only way to initialize a PmTreeConfig
        let config = PmtreeConfig::from_str(config_str.as_str()).unwrap();
        PoseidonTree::new(21, Default::default(), config).unwrap()
    };

    let mut tree_d22 = {
        config_.path = temp_folder_tree_22.path().to_owned();
        let config_str = serde_json::to_string(&config_).unwrap();
        // Note: in Zerokit 0.8 this is the only way to initialize a PmTreeConfig
        let config = PmtreeConfig::from_str(config_str.as_str()).unwrap();
        PoseidonTree::new(22, Default::default(), config).unwrap()
    };

    let mut tree_d22_b2 = {
        config_.path = temp_folder_tree_22_b2.path().to_owned();
        let config_str = serde_json::to_string(&config_).unwrap();
        // Note: in Zerokit 0.8 this is the only way to initialize a PmTreeConfig
        let config = PmtreeConfig::from_str(config_str.as_str()).unwrap();
        PoseidonTree::new(22, Default::default(), config).unwrap()
    };

    let rate_commit = {
        let mut rng = thread_rng();
        Fr::rand(&mut rng)
    };

    let mut group = c.benchmark_group("PmTree set");

    for i in [0, 1000, 10_000, 100_000, 500_000, 750_000, 1_000_000].iter() {
        group.bench_with_input(BenchmarkId::new("PmTree d20 set", i), i, |b, i| {
            b.iter(|| tree_d20.set(black_box(*i), black_box(rate_commit)).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("PmTree d21 set", i), i, |b, i| {
            b.iter(|| tree_d21.set(black_box(*i), black_box(rate_commit)).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("PmTree d22 set", i), i, |b, i| {
            b.iter(|| tree_d22.set(black_box(*i), black_box(rate_commit)).unwrap())
        });
    }

    group.finish();

    let mut group = c.benchmark_group("PmTree merkle proof");

    for i in [0, 1000, 10_000, 100_000, 500_000, 750_000, 1_000_000].iter() {
        group.bench_with_input(BenchmarkId::new("PmTree d20 proof", i), i, |b, i| {
            b.iter(|| {
                tree_d20_b2
                    .set(black_box(*i), black_box(rate_commit))
                    .unwrap();
                let _proof = tree_d20_b2.proof(black_box(*i)).unwrap();
            })
        });
        group.bench_with_input(BenchmarkId::new("PmTree d21 proof", i), i, |b, i| {
            b.iter(|| {
                tree_d21_b2
                    .set(black_box(*i), black_box(rate_commit))
                    .unwrap();
                let _proof = tree_d21_b2.proof(black_box(*i)).unwrap();
            })
        });
        group.bench_with_input(BenchmarkId::new("PmTree d22 proof", i), i, |b, i| {
            b.iter(|| {
                tree_d22_b2
                    .set(black_box(*i), black_box(rate_commit))
                    .unwrap();
                let _proof = tree_d22_b2.proof(black_box(*i)).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark
}
criterion_main!(benches);
