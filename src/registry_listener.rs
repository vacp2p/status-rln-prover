use crate::error::AppError;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::types::Filter;
use alloy::transports::{RpcError, TransportError};
use tonic::codegen::tokio_stream::StreamExt;

type AlloyWsProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

pub(crate) struct RegistryListener {
    rpc_url: String,
    sc_address: Address,
    event: String,
}

impl RegistryListener {
    pub(crate) fn new(rpc_url: &str, sc_address: Address, event: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            sc_address,
            event: event.to_string(),
        }
    }

    /// Create a provider (aka connect to websocket url)
    async fn setup_provider_ws(&self) -> Result<AlloyWsProvider, RpcError<TransportError>> {
        let ws = WsConnect::new(self.rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        Ok(provider)
    }

    /// Listen to Smart Contract specified events
    pub(crate) async fn listen(&self) -> Result<(), AppError> {
        let provider = self.setup_provider_ws().await.map_err(AppError::from)?;

        let filter = Filter::new()
            .address(self.sc_address)
            .event(self.event.as_str())
            .from_block(BlockNumberOrTag::Latest);

        // Subscribe to logs.
        let sub = provider
            .subscribe_logs(&filter)
            .await
            .map_err(AppError::from)?;
        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            println!("Uniswap token logs: {log:?}");
        }

        Ok(())
    }
}
