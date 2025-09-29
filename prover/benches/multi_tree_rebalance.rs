use std::cmp::PartialEq;
use std::fmt::Formatter;
use alloy::primitives::Address;
use criterion::Criterion;
use criterion::{BenchmarkId, Throughput};
use criterion::{criterion_group, criterion_main};
use rand::{Rng, RngCore};
use rln::pm_tree_adapter::{PmTree, PmtreeConfig};
use arbitrary::{Arbitrary, Unstructured};
use mpchash::HashRing;
use rln::poseidon_tree::PoseidonTree;
use rln::protocol::keygen;
use zerokit_utils::Mode::HighThroughput;
use zerokit_utils::ZerokitMerkleTree;

#[derive(Hash, Debug, PartialEq, Clone, Copy)]
struct Node(u64);

struct MultiTree {
    trees: Vec<PmTree>,
    indexes: Vec<usize>,
    ring: HashRing<Node>,
}

impl MultiTree {

    fn fill(&mut self, counts: Vec<usize>) {

        assert_eq!(counts.len(), self.trees.len());

        for (i, expected_count) in counts.iter().enumerate() {

            if *expected_count == 0 {
                break;
            }

            let mut count = 0;
            loop {
                // get some random data:
                // let mut data = [0u8; 20];
                // rand::rng().fill_bytes(&mut data);
                // let mut unstructured = Unstructured::new(&data);
                // let addr = Address::arbitrary(&mut unstructured).unwrap();
                let addr = Address::random();

                if self.ring.node(&addr).unwrap().node() == &Node(i as u64) {
                    let (_id_s, id_co) = keygen();
                    self.trees[i].set(count, id_co).unwrap();
                    count += 1;
                }

                if count >= *expected_count {
                    break;
                }
            }
        }
    }

    fn address_for_node(&self, node_index: u64) -> Address {
        loop {
            let addr = Address::random();
            if self.ring.node(&addr).unwrap().node() == &Node(node_index) {
                return addr;
            }
        }
    }


    fn add_and_rebalance(&mut self, addr: Address) {

        let (_id_s, id_co) = keygen();
        let index = self.ring.node(&addr).unwrap().node().0;

        let tree = &mut self.trees[index as usize];
        let index = self.indexes[index as usize];
        tree.set(index, id_co).unwrap();
        self.indexes[index as usize] += 1;
    }
}

impl std::fmt::Debug for MultiTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MultiTree with {} trees, indexes: {:?}", self.trees.len(), self.indexes)
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {

    let mut multi_tree_2_500 = {

        let temp_folder_tree_1 = tempfile::tempdir().unwrap();
        let temp_folder_tree_2 = tempfile::tempdir().unwrap();
        let tree_config = PmtreeConfig::builder()
            .path(temp_folder_tree_1.path().to_path_buf())
            .temporary(false)
            .cache_capacity(100_000)
            .flush_every_ms(12_000)
            .mode(HighThroughput)
            .use_compression(false)
            .build()
            .unwrap();
        let tree_1 = PoseidonTree::new(20, Default::default(), tree_config).unwrap();

        let tree_config_2 = PmtreeConfig::builder()
            .path(temp_folder_tree_2.path().to_path_buf())
            .temporary(false)
            .cache_capacity(100_000)
            .flush_every_ms(12_000)
            .mode(HighThroughput)
            .use_compression(false)
            .build()
            .unwrap();
        let tree_2 = PoseidonTree::new(20, Default::default(), tree_config_2).unwrap();

        MultiTree {
            trees: vec![
                tree_1,
                tree_2,
            ],
            indexes: vec![0, 0],
            ring: Default::default(),
        }
    };

    multi_tree_2_500.fill(vec![499, 0]);
    let next_address = multi_tree_2_500.address_for_node(0);

    multi_tree_2_500.add_and_rebalance(next_address);


    let mut group = c.benchmark_group("Multi tree rebalance");



    /*
    for i in [0, 1000, 10_000, 100_000, 500_000, 750_000, 1_000_000].iter() {
        group.bench_with_input(BenchmarkId::new("PmTree d20 set", i), i, |b, i| {
            b.iter(|| {
                tree_d20.set(black_box(*i), black_box(rate_commit)).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("PmTree d21 set", i), i, |b, i| {
            b.iter(|| {
                tree_d21.set(black_box(*i), black_box(rate_commit)).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("PmTree d22 set", i), i, |b, i| {
            b.iter(|| {
                tree_d22.set(black_box(*i), black_box(rate_commit)).unwrap()
            })
        });
    }
    */

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        // .sample_size(10)
        // .measurement_time(Duration::from_secs(500))
    ;
    targets = criterion_benchmark
);
criterion_main!(benches);