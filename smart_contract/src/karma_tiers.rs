use std::collections::BTreeMap;
// third-party
use alloy::{
    primitives::{Address, U256},
    providers::{ProviderBuilder, WsConnect},
    sol,
};
use derive_more::From;
use url::Url;
// internal
use crate::AlloyWsProvider;

sol! {
    // https://github.com/vacp2p/staking-reward-streamer/pull/224
    #[sol(rpc)]
    contract KarmaTiersSC {

        /// @notice Emitted when a new tier is added
        event TierAdded(uint8 indexed tierId, string name, uint256 minKarma, uint256 maxKarma, uint32 txPerEpoch);
        /// @notice Emitted when a tier is updated
        event TierUpdated(uint8 indexed tierId, string name, uint256 minKarma, uint256 maxKarma, uint32 txPerEpoch);

        struct Tier {
            uint256 minKarma;
            uint256 maxKarma;
            string name;
            uint32 txPerEpoch;
            bool active;
        }

        mapping(uint8 id => Tier tier) public tiers;
        uint8 public currentTierId;
    }
}

impl KarmaTiersSC::KarmaTiersSCInstance<AlloyWsProvider> {
    /// Read smart contract `tiers` mapping
    pub async fn get_tiers(
        ws_rpc_url: Url,
        sc_address: Address,
    ) -> Result<BTreeMap<TierIndex, Tier>, alloy::contract::Error> {
        let ws = WsConnect::new(ws_rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        let karma_tiers_sc = KarmaTiersSC::new(sc_address, provider.clone());

        let current_tier_id = karma_tiers_sc.currentTierId().call().await?;

        let mut tiers = BTreeMap::new();

        // Note: By design, karmaTiers first id is 1
        for i in 1..=current_tier_id {
            let tiers_at = karma_tiers_sc.tiers(i).call().await?;

            tiers.insert(TierIndex::from(i), tiers_at.into());
        }

        Ok(tiers)
    }
}

#[derive(Debug, Clone, Default, Copy, From, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TierIndex(u8);

impl From<&TierIndex> for u8 {
    fn from(value: &TierIndex) -> u8 {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tier {
    pub min_karma: U256,
    pub max_karma: U256,
    pub name: String,
    pub tx_per_epoch: u32,
    pub active: bool,
}

impl From<KarmaTiersSC::TierAdded> for Tier {
    fn from(tier_added: KarmaTiersSC::TierAdded) -> Self {
        Self {
            min_karma: tier_added.minKarma,
            max_karma: tier_added.maxKarma,
            name: tier_added.name,
            tx_per_epoch: tier_added.txPerEpoch,
            active: true,
        }
    }
}

impl From<KarmaTiersSC::TierUpdated> for Tier {
    fn from(tier_updated: KarmaTiersSC::TierUpdated) -> Self {
        Self {
            min_karma: tier_updated.minKarma,
            max_karma: tier_updated.maxKarma,
            name: tier_updated.name,
            tx_per_epoch: tier_updated.txPerEpoch,
            active: true,
        }
    }
}

impl From<KarmaTiersSC::tiersReturn> for Tier {
    fn from(tiers_return: KarmaTiersSC::tiersReturn) -> Self {
        Self {
            min_karma: tiers_return._0,
            max_karma: tiers_return._1,
            name: tiers_return._2,
            tx_per_epoch: tiers_return._3,
            active: tiers_return._4,
        }
    }
}
