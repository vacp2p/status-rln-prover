use ark_bn254::Fr;
use derive_more::{Add, From, Into};

#[derive(Debug, Clone, Copy, From, Into)]
pub(crate) struct MerkleTreeIndex(usize);

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
