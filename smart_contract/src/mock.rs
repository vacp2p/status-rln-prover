use crate::karma_tiers::{Tier, TierIndex};
use crate::{KarmaAmountExt, RLNRegister};
use alloy::primitives::{Address, U256};
use async_trait::async_trait;
use log::debug;
use std::collections::BTreeMap;
use std::sync::LazyLock;

pub struct MockKarmaSc {}

#[async_trait]
impl KarmaAmountExt for MockKarmaSc {
    type Error = alloy::contract::Error;

    async fn karma_amount(&self, _address: &Address) -> Result<U256, Self::Error> {
        Ok(U256::from(10))
    }
}

pub struct MockKarmaRLNSc {}

#[async_trait]
impl RLNRegister for MockKarmaRLNSc {
    type Error = alloy::contract::Error;

    async fn register(&self, identity_commitment: U256) -> Result<(), Self::Error> {
        debug!(
            "Register user with identity_commitment: {:?}",
            identity_commitment
        );
        Ok(())
    }
}

pub static TIER_LIMITS: LazyLock<BTreeMap<TierIndex, Tier>> = LazyLock::new(|| {
    BTreeMap::from([
        (
            TierIndex::from(0),
            Tier {
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                name: "Basic".to_string(),
                active: true,
            }, // KarmaAmount::from(10),
               // (TierLimit(6), TierName::from("Basic")),
        ),
        (
            TierIndex::from(1),
            Tier {
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                name: "Active".to_string(),
                active: true,
            }, // KarmaAmount::from(50),
               // (TierLimit(120), TierName::from("Active")),
        ),
        (
            TierIndex::from(2),
            Tier {
                min_karma: U256::from(100),
                max_karma: U256::from(499),
                name: "Regular".to_string(),
                active: true,
            }, // KarmaAmount::from(100),
               // (TierLimit(720), TierName::from("Regular")),
        ),
        (
            TierIndex::from(3),
            Tier {
                min_karma: U256::from(500),
                max_karma: U256::from(999),
                name: "Power User".to_string(),
                active: true,
            }, // KarmaAmount::from(1000),
               // (TierLimit(86400), TierName::from("Power User")),
        ),
        (
            TierIndex::from(4),
            Tier {
                min_karma: U256::from(1000),
                max_karma: U256::from(4999),
                name: "S-Tier".to_string(),
                active: true,
            }, // KarmaAmount::from(5000),
               // (TierLimit(432000), TierName::from("S-Tier")),
        ),
    ])
});
