use std::collections::BTreeMap;
use std::sync::LazyLock;
// third-party
use alloy::primitives::U256;
use derive_more::{From, Into};

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

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, From, Into)]
pub struct TierLimit(u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash, From, Into)]
pub struct TierName(String);

impl From<&str> for TierName {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

pub static TIER_LIMITS: LazyLock<BTreeMap<KarmaAmount, (TierLimit, TierName)>> =
    LazyLock::new(|| {
        BTreeMap::from([
            (
                KarmaAmount::from(10),
                (TierLimit(6), TierName::from("Basic")),
            ),
            (
                KarmaAmount::from(50),
                (TierLimit(120), TierName::from("Active")),
            ),
            (
                KarmaAmount::from(100),
                (TierLimit(720), TierName::from("Regular")),
            ),
            (
                KarmaAmount::from(500),
                (TierLimit(14440), TierName::from("Regular")),
            ),
            (
                KarmaAmount::from(1000),
                (TierLimit(86400), TierName::from("Power User")),
            ),
            (
                KarmaAmount::from(5000),
                (TierLimit(432000), TierName::from("S-Tier")),
            ),
        ])
    });
