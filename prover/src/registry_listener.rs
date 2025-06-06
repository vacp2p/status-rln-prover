// third-party
use alloy::{
    contract::Error as AlloyContractError,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, WsConnect},
    sol_types::SolEvent,
    transports::{RpcError, TransportError},
};
use tonic::codegen::tokio_stream::StreamExt;
use tracing::{debug, error, info};
// internal
use crate::error::{AppError, HandleTransferError, RegisterError};
use crate::karma_sc::{KarmaAmountExt, KarmaSC};
use crate::sc::AlloyWsProvider;
use crate::user_db_service::UserDb;

pub(crate) struct RegistryListener {
    rpc_url: String,
    sc_address: Address,
    user_db: UserDb,
    minimal_amount: U256,
}

impl RegistryListener {
    pub(crate) fn new(
        rpc_url: &str,
        sc_address: Address,
        user_db: UserDb,
        minimal_amount: U256,
    ) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            sc_address,
            user_db,
            minimal_amount,
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
        let karma_sc = KarmaSC::new(self.sc_address, provider.clone());

        let filter = alloy::rpc::types::Filter::new()
            .address(self.sc_address)
            .event(KarmaSC::Transfer::SIGNATURE);

        // Subscribe to logs matching the filter.
        let subscription = provider.subscribe_logs(&filter).await?;
        let mut stream = subscription.into_stream();

        // Loop through the incoming event logs
        while let Some(log) = stream.next().await {
            match KarmaSC::Transfer::decode_log_data(log.data()) {
                Ok(transfer_event) => {
                    match self.handle_transfer_event(&karma_sc, transfer_event).await {
                        Ok(addr) => {
                            info!("Registered new user: {}", addr);
                        }
                        Err(HandleTransferError::Register(RegisterError::AlreadyRegistered(
                            address,
                        ))) => {
                            debug!("Already registered: {}", address);
                        }
                        Err(e) => {
                            error!("Unexpected error: {}", e);
                            // FIXME: return / continue?
                            return Err(AppError::RegistryError(e));
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Error decoding log data: {:?}", e);
                    // It's also useful to print the raw log data for debugging
                    eprintln!("Raw log topics: {:?}", log.topics());
                    eprintln!("Raw log data: {:?}", log.data());
                }
            }
        }

        Ok(())
    }

    // async fn handle_transfer_event(&self, karma_sc: &KarmaSCInstance<AlloyWsProvider>, transfer_event: KarmaSC::Transfer) -> Result<(), HandleTransferError> {
    async fn handle_transfer_event<E: Into<AlloyContractError>, KSC: KarmaAmountExt<Error = E>>(
        &self,
        karma_sc: &KSC,
        transfer_event: KarmaSC::Transfer,
    ) -> Result<Address, HandleTransferError> {
        let from_address: Address = transfer_event.from;
        let to_address: Address = transfer_event.to;
        let amount: U256 = transfer_event.value;

        // This is a mint event if from_address is the zero address
        if from_address == Address::default() {
            let should_register = {
                if amount >= self.minimal_amount {
                    true
                } else {
                    let balance = karma_sc
                        .karma_amount(&to_address)
                        .await
                        .map_err(|e| HandleTransferError::BalanceOf(e.into()))?;
                    balance >= self.minimal_amount
                }
            };

            if should_register {
                self.user_db
                    .on_new_user(to_address)
                    .map_err(HandleTransferError::Register)?;
            }
        }

        Ok(to_address)
    }
}

#[cfg(test)]
mod tests {
    use crate::epoch_service::{Epoch, EpochSlice};
    use alloy::primitives::address;
    use parking_lot::RwLock;
    use std::sync::Arc;
    // use crate::tier::TIER_LIMITS;
    use super::*;
    use crate::user_db_service::UserDbService;

    // const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");
    struct MockKarmaSc {}

    impl KarmaAmountExt for MockKarmaSc {
        type Error = AlloyContractError;
        async fn karma_amount(&self, _address: &Address) -> Result<U256, Self::Error> {
            Ok(U256::from(10))
        }
    }

    #[tokio::test]
    async fn test_handle_transfer_event() {
        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let user_db_service = UserDbService::new(Default::default(), epoch_store, 10.into());
        let user_db = user_db_service.get_user_db();

        assert!(user_db_service.get_user_db().get_user(&ADDR_2).is_none());

        let minimal_amount = U256::from(25);
        let registry = RegistryListener {
            rpc_url: "".to_string(),
            sc_address: Default::default(),
            user_db,
            minimal_amount: U256::from(25),
        };

        let transfer = KarmaSC::Transfer {
            from: Address::default(),
            to: ADDR_2,
            value: minimal_amount,
        };

        let karma_sc = MockKarmaSc {};
        registry
            .handle_transfer_event(&karma_sc, transfer)
            .await
            .unwrap();

        assert!(user_db_service.get_user_db().get_user(&ADDR_2).is_some());
    }
}
