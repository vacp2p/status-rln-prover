// third-party
use alloy::primitives::U256;
use alloy::{
    primitives::Address,
    providers::{ProviderBuilder, WsConnect},
    sol,
    transports::{RpcError, TransportError},
};
use async_trait::async_trait;
use url::Url;
// internal
use crate::AlloyWsProvider;

#[async_trait]
pub trait RLNRegister {
    type Error;

    async fn register(&self, identity_commitment: U256) -> Result<(), Self::Error>;
}

sol! {
    // https://github.com/vacp2p/staking-reward-streamer/pull/220
    #[sol(rpc)]
    contract KarmaRLNSC {
        function register(uint256 identityCommitment) external onlyRole(REGISTER_ROLE);
    }
}

impl KarmaRLNSC::KarmaRLNSCInstance<AlloyWsProvider> {
    pub async fn try_new(rpc_url: Url, address: Address) -> Result<Self, RpcError<TransportError>> {
        let ws = WsConnect::new(rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        Ok(KarmaRLNSC::new(address, provider))
    }
}

#[async_trait]
impl RLNRegister for KarmaRLNSC::KarmaRLNSCInstance<AlloyWsProvider> {
    type Error = alloy::contract::Error;

    async fn register(&self, identity_commitment: U256) -> Result<(), Self::Error> {
        self.register(identity_commitment).call().await?;
        Ok(())
    }
}
