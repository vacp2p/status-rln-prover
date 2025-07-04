// third-party
use alloy::{
    primitives::{Address, U256},
    providers::{ProviderBuilder, WsConnect},
    sol,
    transports::{RpcError, TransportError},
};
use async_trait::async_trait;
use url::Url;
// internal
use crate::AlloyWsProvider;

#[async_trait]
pub trait KarmaAmountExt {
    type Error;

    async fn karma_amount(&self, address: &Address) -> Result<U256, Self::Error>;
}

sol! {
    // https://github.com/vacp2p/staking-reward-streamer/blob/main/src/Karma.sol
    #[sol(rpc)]
    contract KarmaSC {
        // From: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol#L16
        event Transfer(address indexed from, address indexed to, uint256 value);

        function balanceOf(address account) public view override returns (uint256);
    }
}

impl KarmaSC::KarmaSCInstance<AlloyWsProvider> {
    pub async fn try_new(rpc_url: Url, address: Address) -> Result<Self, RpcError<TransportError>> {
        let ws = WsConnect::new(rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        Ok(KarmaSC::new(address, provider))
    }
}

#[async_trait]
impl KarmaAmountExt for KarmaSC::KarmaSCInstance<AlloyWsProvider> {
    type Error = alloy::contract::Error;
    async fn karma_amount(&self, address: &Address) -> Result<U256, Self::Error> {
        self.balanceOf(*address).call().await
    }
}
