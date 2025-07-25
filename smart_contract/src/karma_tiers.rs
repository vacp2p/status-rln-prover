use std::ops::Add;
// third-party
use alloy::{
    primitives::{Address, U256},
    providers::{ProviderBuilder, WsConnect},
    sol,
};
use alloy::providers::{MulticallError, Provider};
use alloy::transports::{RpcError, TransportErrorKind};
use derive_more::From;
use url::Url;
// internal
use crate::AlloyWsProvider;

sol! {
    // https://github.com/vacp2p/staking-reward-streamer/pull/224
    #[sol(rpc)]
    contract KarmaTiersSC {

        event TiersUpdated();

        struct Tier {
            uint256 minKarma;
            uint256 maxKarma;
            string name;
            uint32 txPerEpoch;
        }

        // mapping(uint8 id => Tier tier) public tiers;
        // uint8 public currentTierId;
        Tier[] public tiers;

        function getTierCount() external view returns (uint256 count);

    }
}

impl KarmaTiersSC::KarmaTiersSCInstance<AlloyWsProvider> {

    /// Read smart contract `tiers` mapping
    pub async fn get_tiers(
        ws_rpc_url: Url,
        sc_address: Address,
    ) -> Result<Vec<Tier>, GetScTiersError> {

        let ws = WsConnect::new(ws_rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await
            .map_err(GetScTiersError::RpcTransportError)?;

        Self::get_tiers_from_provider(&provider, sc_address).await
    }

    pub async fn get_tiers_from_provider(provider: &AlloyWsProvider, sc_address: Address) -> Result<Vec<Tier>, GetScTiersError> {

        let karma_tiers_sc = KarmaTiersSC::new(sc_address, provider.clone());

        let tier_count = karma_tiers_sc.getTierCount()
        .call()
        .await
        .map_err(GetScTiersError::Alloy)?;

        if tier_count > U256::from(u16::MAX) {
        return Err(GetScTiersError::TierCount);
        }
        // Note: unwrap safe - just tested
        let tier_count = usize::try_from(tier_count).unwrap();

        let mut multicall = provider.multicall().dynamic();
        for i in 0..tier_count {
        multicall = multicall.add_dynamic(karma_tiers_sc.tiers(U256::from(i)));
        }

        multicall
            .aggregate3()
            .await
            .map_err(GetScTiersError::Multicall)?
            .into_iter()
            .map(|t| t.map(Tier::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_e| GetScTiersError::MulticallInner)
    }
}


#[derive(Debug, thiserror::Error)]
pub enum GetScTiersError {
    // #[error("Rpc error 1: {0}")]
    // RpcError(#[from] RpcError<RpcError<TransportErrorKind>>),
    #[error("Rpc transport error 2: {0}")]
    RpcTransportError(#[from] RpcError<TransportErrorKind>),
    #[error(transparent)]
    Alloy(#[from] alloy::contract::Error),
    #[error(transparent)]
    Multicall(MulticallError),
    #[error("Error retrieving tier from multicall SC")]
    MulticallInner,
    #[error("Tier count too high (exceeds u16)")]
    TierCount
}

#[derive(Debug, Clone, Default, Copy, From, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TierIndex(u8);

impl From<&TierIndex> for u8 {
    fn from(value: &TierIndex) -> u8 {
        value.0
    }
}

impl Add<u8> for TierIndex {
    type Output = TierIndex;

    fn add(self, rhs: u8) -> Self::Output {
        Self(self.0 + rhs)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tier {
    pub min_karma: U256,
    pub max_karma: U256,
    pub name: String,
    pub tx_per_epoch: u32,
    // pub active: bool,
}

/*
impl From<KarmaTiersSC::TierAdded> for Tier {
    fn from(tier_added: KarmaTiersSC::TierAdded) -> Self {
        Self {
            min_karma: tier_added.minKarma,
            max_karma: tier_added.maxKarma,
            name: tier_added.name,
            tx_per_epoch: tier_added.txPerEpoch,
            // active: true,
        }
    }
}
*/

/*
impl From<KarmaTiersSC::TierUpdated> for Tier {
    fn from(tier_updated: KarmaTiersSC::TierUpdated) -> Self {
        Self {
            min_karma: tier_updated.minKarma,
            max_karma: tier_updated.maxKarma,
            name: tier_updated.name,
            tx_per_epoch: tier_updated.txPerEpoch,
            // active: true,
        }
    }
}
*/

impl From<KarmaTiersSC::tiersReturn> for Tier {
    fn from(tiers_return: KarmaTiersSC::tiersReturn) -> Self {
        Self {
            min_karma: tiers_return._0,
            max_karma: tiers_return._1,
            name: tiers_return._2,
            tx_per_epoch: tiers_return._3,
            // active: tiers_return._4,
        }
    }
}
