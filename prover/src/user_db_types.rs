use ark_bn254::Fr;
use derive_more::{Add, From, Into};

/// A wrapper type over u64
#[derive(Debug, Clone, Copy, From, Into, PartialEq)]
pub(crate) struct MerkleTreeIndex(u64);

impl From<MerkleTreeIndex> for usize {
    fn from(value: MerkleTreeIndex) -> Self {
        // TODO: compile time assert
        value.0 as usize
    }
}

/// A wrapper type over u64
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
