use std::cmp::Ordering;
use std::fmt::Formatter;
use std::time::Instant;
// third-party
use mpchash::{HashRing, KeyRange, RingPosition};
use alloy::primitives::Address;
use tracing_test::traced_test;
// RLN
use rln::poseidon_tree::PoseidonTree;
use rln::protocol::keygen;
use rln::pm_tree_adapter::{PmTree, PmtreeConfig};
use zerokit_utils::Mode::HighThroughput;
use zerokit_utils::ZerokitMerkleTree;

#[derive(Hash, Debug, PartialEq, Clone, Copy)]
struct Node(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeKeyRange(KeyRange<RingPosition>);

impl PartialOrd for NodeKeyRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.0.start < other.0.start {
            Some(Ordering::Less)
        } else if self.0.start == other.0.start && self.0.end == other.0.end {
            Some(Ordering::Equal)
        } else if self.0.start > other.0.start {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl Ord for NodeKeyRange {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

struct MultiTree {
    trees: Vec<PmTree>,
    addresses: Vec<Vec<Address>>,
    indexes: Vec<usize>,
    ring: HashRing<Node>,
}

impl MultiTree {
    fn new(count: usize) -> Self {

        let ring = HashRing::new();
        (0..count).for_each(|i| {
            ring.add(Node(i as u64))
        });
        MultiTree {
            trees: (0..count).map(|_| pmtree_new()).collect(),
            addresses: vec![vec![]; count],
            indexes: vec![0; count],
            ring,
        }
    }

    fn fill(&mut self, counts: Vec<usize>) {

        assert_eq!(counts.len(), self.trees.len());

        for (i, expected_count) in counts.iter().enumerate() {

            if *expected_count == 0 {
                break;
            }

            let mut count = 0;
            loop {
                // get some random address
                let addr = Address::random();
                let token = self
                    .ring
                    .node(&addr)
                    .unwrap()
                    // .node();
                    ;

                // println!("addr: {} - t node : {:?}", addr, token);

                if token.node() == &Node(i as u64) {
                    let (_id_s, id_co) = keygen();
                    self.trees[i].set(count, id_co).unwrap();
                    self.addresses[i].push(addr);
                    count += 1;
                }

                if count >= *expected_count {
                    break;
                }

                // if count % 5 == 0 {
                //     println!("{}/{}", count, *expected_count);
                // }
            }
        }
    }

    /*
    fn address_for_node(&self, node_index: u64) -> Address {
        loop {
            let addr = Address::random();
            if self.ring.node(&addr).unwrap().node() == &Node(node_index) {
                return addr;
            }
        }
    }
    */

    /*
    fn add_and_rebalance(&mut self, addr: Address) {

        let (_id_s, id_co) = keygen();
        let index = self.ring.node(&addr).unwrap().node().0;

        let tree = &mut self.trees[index as usize];
        let index = self.indexes[index as usize];
        tree.set(index, id_co).unwrap();
        self.indexes[index as usize] += 1;
    }
    */

    fn rebalance(&mut self) {

        let num_nodes = self.ring.len();
        /*
        let node_ranges: BTreeMap<NodeKeyRange, Node> = (1..=num_nodes).map(|i| {
            let pos = self.ring.position(&Node(i as u64));
            (NodeKeyRange(self.ring.key_range(pos).unwrap()), Node(i as u64))
        }).collect();
        */

        let node_0_pos = self.ring.position(&Node(0));
        let node_0_key_range = self.ring.key_range(node_0_pos).unwrap();
        let node_1_pos = self.ring.position(&Node(1));
        let node_1_key_range = self.ring.key_range(node_1_pos).unwrap();

        let new_node = Node(2);
        self.ring.add(new_node);
        self.trees.push(pmtree_new());
        self.addresses.push(vec![]);

        let node_0_pos_a = self.ring.position(&Node(0));
        let node_0_key_range_a = self.ring.key_range(node_0_pos).unwrap();
        let node_1_pos_a = self.ring.position(&Node(1));
        let node_1_key_range_a = self.ring.key_range(node_1_pos).unwrap();
        let node_2_pos = self.ring.position(&Node(2));
        let node_2_key_range = self.ring.key_range(node_2_pos).unwrap();

        println!("before add - node_0_key_range: {:?}", node_0_key_range);
        println!("before add - node_1_key_range: {:?}", node_1_key_range);
        println!("after add - node_0_key_range: {:?}", node_0_key_range_a);
        println!("after add - node_1_key_range: {:?}", node_1_key_range_a);
        println!("after add - node_2_key_range: {:?}", node_2_key_range);

        // Ensure that Node 0 is affected by the addition of Node 2
        assert_eq!(node_2_key_range.start, node_0_key_range.start);
        assert!(node_2_key_range.end < node_0_key_range.end);

        let extracted: Vec<(usize, Address)> = self.addresses[0]
            .iter()
            .enumerate()
            .filter(|(i, a)| {
                let token_ = self.ring.node(&a).expect("empty ring");
                token_.node() == &new_node
            })
            .map(|(i, a)| (i, a.clone()))
            .collect();

        println!("extracted len: {:?}", extracted.len());

        // Update Node 0

        let indexes_to_remove: Vec<usize> = extracted.iter().map(|(i, _a)| *i).collect();
        self.trees[0].override_range(0, vec![].into_iter(), indexes_to_remove.into_iter()).unwrap();

        // Update Node 2

        self.addresses[2].extend(extracted.iter().map(|(_, a)| a.clone()));

        let rln_ids: Vec<_> = extracted.iter().map(|(_, a)| keygen().1).collect();
        self.trees[2].override_range(0, rln_ids.into_iter(), vec![].into_iter()).unwrap();
    }

}

impl std::fmt::Debug for MultiTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MultiTree with {} trees, indexes: {:?}", self.trees.len(), self.indexes)
    }
}

pub fn pmtree_new() -> PmTree {

    let temp_folder_tree_0 = tempfile::tempdir().unwrap();
    let tree_config_0 = PmtreeConfig::builder()
        .path(temp_folder_tree_0.path().to_path_buf())
        .temporary(false)
        .cache_capacity(100_000)
        .flush_every_ms(12_000)
        .mode(HighThroughput)
        .use_compression(false)
        .build()
        .unwrap();
    let tree_0 = PoseidonTree::new(20, Default::default(), tree_config_0).unwrap();
    tree_0
}

#[test]
#[traced_test]
fn test_multi_tree_rebalance() {

    let mut multi_tree_2_500 = MultiTree::new(2);
    let start = Instant::now();
    multi_tree_2_500.fill(vec![500, 0]);
    println!("500 - Fill elapsed: {} ms", start.elapsed().as_millis());

    let mut multi_tree_2_1000 = MultiTree::new(2);
    let start = Instant::now();
    multi_tree_2_1000.fill(vec![1000, 0]);
    println!("1000 - Fill elapsed: {} ms", start.elapsed().as_millis());

    let mut multi_tree_2_10_000 = MultiTree::new(2);
    let start = Instant::now();
    multi_tree_2_10_000.fill(vec![10_000, 0]);
    println!("10_000 - Fill elapsed: {} ms", start.elapsed().as_millis());

    let mut multi_tree_2_100_000 = MultiTree::new(2);
    let start = Instant::now();
    multi_tree_2_100_000.fill(vec![100_000, 0]);
    println!("100_000 - Fill elapsed: {} ms", start.elapsed().as_millis());

    let start = Instant::now();
    multi_tree_2_500.rebalance();
    println!("500 - rebalance: {} ms", start.elapsed().as_millis());

    let start = Instant::now();
    multi_tree_2_1000.rebalance();
    println!("1000 - rebalance: {} ms", start.elapsed().as_millis());

    let start = Instant::now();
    multi_tree_2_10_000.rebalance();
    println!("10_000 - rebalance: {} ms", start.elapsed().as_millis());

    let start = Instant::now();
    multi_tree_2_100_000.rebalance();
    println!("100_000 - rebalance: {} ms", start.elapsed().as_millis());
}