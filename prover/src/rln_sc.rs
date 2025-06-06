use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::sol;
use alloy::transports::{RpcError, TransportError};
use url::Url;
// FIXME
use crate::registry_listener::AlloyWsProvider;
use crate::rln_sc::KarmaRLNSC::KarmaRLNSCInstance;

sol! {
    // https://github.com/vacp2p/staking-reward-streamer/pull/220
    #[sol(rpc)]
    contract KarmaRLNSC {
        function register(uint256 identityCommitment) external onlyRole(REGISTER_ROLE);
    }
}

impl KarmaRLNSCInstance<AlloyWsProvider> {
    pub(crate) async fn try_new(
        rpc_url: Url,
        address: Address,
    ) -> Result<Self, RpcError<TransportError>> {
        let ws = WsConnect::new(rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        Ok(KarmaRLNSC::new(address, provider))
    }
}
