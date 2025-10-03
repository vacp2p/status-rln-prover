use ark_bn254::Fr;
use derive_more::{Add, From, Into};

/// An index to a tree (wrapper over u64)
/// 
/// As the prover handles multiple merkle trees, we need to know in which tree is an address
#[derive(Debug, Clone, Copy, From, Into, PartialEq)]
pub(crate) struct TreeIndex(u64);

impl From<TreeIndex> for usize {
    fn from(value: TreeIndex) -> Self {
        const _: () = assert!(
            size_of::<u64>() == size_of::<usize>(),
            "Expect usize to have the same size as of u64"
        );
        value.0 as usize
    }
}

/// An index in a merkle tree (wrapper over u64)
#[derive(Debug, Clone, Copy, From, Into, PartialEq)]
pub(crate) struct IndexInMerkleTree(u64);

impl From<IndexInMerkleTree> for usize {
    fn from(value: IndexInMerkleTree) -> Self {
        const _: () = assert!(
            size_of::<u64>() == size_of::<usize>(),
            "Expect usize to have the same size as of u64"
        );
        value.0 as usize
    }
}

/// A rate limit for a user address
/// 
/// This is also referred as the "spam limit": 
/// the max number of messages that a user can send before being slashed
#[derive(Debug, Clone, Copy, Default, PartialOrd, PartialEq, From, Into)]
pub struct RateLimit(u64);

impl RateLimit {
    pub(crate) const ZERO: RateLimit = RateLimit(0);

    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl From<RateLimit> for Fr {
    fn from(rate_limit: RateLimit) -> Self {
        Fr::from(rate_limit.0)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, From, Into, Add)]
pub(crate) struct EpochCounter(u64);

#[derive(Debug, Default, Clone, Copy, PartialEq, From, Into, Add)]
pub(crate) struct EpochSliceCounter(u64);
