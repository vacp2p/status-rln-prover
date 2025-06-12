// third-party
use derive_more::{From, Into};

/*
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, From)]
pub struct KarmaAmount(U256);

impl KarmaAmount {
    pub(crate) const ZERO: KarmaAmount = KarmaAmount(U256::ZERO);
}

impl From<u64> for KarmaAmount {
    fn from(value: u64) -> Self {
        Self(U256::from(value))
    }
}
*/

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, From, Into)]
pub struct TierLimit(u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash, From, Into)]
pub struct TierName(String);

impl From<&str> for TierName {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}
