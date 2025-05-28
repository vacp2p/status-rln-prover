use std::collections::BTreeMap;
use std::sync::LazyLock;
// third-party
use alloy::primitives::U256;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct KarmaAmount(U256);

impl KarmaAmount {
    pub(crate) const ZERO: KarmaAmount = KarmaAmount(U256::ZERO);
}

impl From<U256> for KarmaAmount {
    fn from(value: U256) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TierLimit(u64);

impl From<TierLimit> for u64 {
    fn from(value: TierLimit) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TierName(pub(crate) String);

impl From<&str> for TierName {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<TierName> for String {
    fn from(value: TierName) -> Self {
        value.0
    }
}

pub static TIER_LIMITS: LazyLock<BTreeMap<KarmaAmount, (TierLimit, TierName)>> = LazyLock::new(|| {
    BTreeMap::from([
        (
            KarmaAmount(U256::from(10)),
            (TierLimit(6), TierName::from("Basic")),
        ),
        (
            KarmaAmount(U256::from(50)),
            (TierLimit(120), TierName::from("Active")),
        ),
        (
            KarmaAmount(U256::from(100)),
            (TierLimit(720), TierName::from("Regular")),
        ),
        (
            KarmaAmount(U256::from(500)),
            (TierLimit(14440), TierName::from("Regular")),
        ),
        (
            KarmaAmount(U256::from(1000)),
            (TierLimit(86400), TierName::from("Power User")),
        ),
        (
            KarmaAmount(U256::from(5000)),
            (TierLimit(432000), TierName::from("S-Tier")),
        ),
    ])
});

