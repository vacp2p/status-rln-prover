// third-party
use alloy::{
    primitives::Address,
    providers::{ProviderBuilder, WsConnect},
    sol,
    transports::{RpcError, TransportError},
};
use url::Url;
// internal
use crate::AlloyWsProvider;

sol! {
    // https://github.com/vacp2p/staking-reward-streamer/pull/220
    #[sol(rpc)]
    contract KarmaRLNSC {
        function register(uint256 identityCommitment) external onlyRole(REGISTER_ROLE);
    }
}

impl KarmaRLNSC::KarmaRLNSCInstance<AlloyWsProvider> {
    pub async fn try_new(
        rpc_url: Url,
        address: Address,
    ) -> Result<Self, RpcError<TransportError>> {
        let ws = WsConnect::new(rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        Ok(KarmaRLNSC::new(address, provider))
    }
}
