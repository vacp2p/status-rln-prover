use std::str::FromStr;
// third-party
use alloy::{
    contract::Error as AlloyContractError,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, WsConnect},
    sol_types::SolEvent,
    transports::{RpcError, TransportError},
};
use alloy::signers::local::PrivateKeySigner;
use tonic::codegen::tokio_stream::StreamExt;
use num_bigint::BigUint;
use tracing::{debug, error, info};
use zeroize::Zeroizing;
// internal
use crate::error::{AppError, HandleTransferError, RegisterSCError};
use crate::user_db::UserDb;
use crate::user_db_error::RegisterError;
use smart_contract::{AlloyWsProvider, KarmaAmountExt, KarmaSC, KarmaRLNSC, RLNRegister, AlloyWsProviderWithSigner};

pub(crate) struct RegistryListener {
    rpc_url: String,
    karma_sc_address: Address,
    rln_sc_address: Address,
    user_db: UserDb,
    minimal_amount: U256,
    private_key: Zeroizing<String>,
}

impl RegistryListener {
    pub(crate) fn new(
        rpc_url: &str,
        karma_sc_address: Address,
        rln_sc_address: Address,
        user_db: UserDb,
        minimal_amount: U256,
        private_key: Zeroizing<String>,
    ) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            karma_sc_address,
            rln_sc_address,
            user_db,
            minimal_amount,
            private_key,
        }
    }

    /// Create a provider (aka connect to websocket url)
    async fn setup_provider_ws(&self) -> Result<AlloyWsProvider, RpcError<TransportError>> {
        let ws = WsConnect::new(self.rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        Ok(provider)
    }

    /// Create a provider with signer (aka connect to websocket url)
    async fn setup_provider_with_signer(&self, private_key: Zeroizing<String>) -> Result<AlloyWsProviderWithSigner, RpcError<TransportError>> {

        // no unwrap
        let signer = PrivateKeySigner::from_str(&private_key).unwrap();

        let ws = WsConnect::new(self.rpc_url.as_str());
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_ws(ws)
            .await?;
        Ok(provider)
    }

    /// Listen to Smart Contract specified events
    pub(crate) async fn listen(&self) -> Result<(), AppError> {
        let provider = self.setup_provider_ws().await.map_err(AppError::from)?;
        let karma_sc = KarmaSC::new(self.karma_sc_address, provider.clone());

        let provider_with_signer = self.setup_provider_with_signer(self.private_key.clone())
            .await
            .map_err(AppError::from)?;
        let rln_sc = KarmaRLNSC::new(self.rln_sc_address, provider_with_signer);

        let filter = alloy::rpc::types::Filter::new()
            .address(self.karma_sc_address)
            .event(KarmaSC::Transfer::SIGNATURE);

        // Subscribe to logs matching the filter.
        let subscription = provider.subscribe_logs(&filter).await?;
        let mut stream = subscription.into_stream();

        // Loop through the incoming event logs
        while let Some(log) = stream.next().await {
            match KarmaSC::Transfer::decode_log_data(log.data()) {
                Ok(transfer_event) => {
                    match self.handle_transfer_event(&karma_sc, &rln_sc, transfer_event).await {
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
                            // Note: Err(e) == HandleTransferError::FetchBalanceOf
                            //       if we cannot fetch the user balance, something is seriously wrong
                            //       and the prover will fail here
                            return Err(AppError::RegistryError(e));
                        }
                    };
                }
                Err(e) => {
                    error!("Error decoding log data: {:?}", e);
                    // It's also useful to print the raw log data for debugging
                    error!("Raw log topics: {:?}", log.topics());
                    error!("Raw log data: {:?}", log.data());
                    // Note: - Assume that SC code has been updated but not the Prover
                    //       - Assume that in the update process, the Prover has not been shutdown (yet)
                    //         in order to avoid a too long service interruption?
                }
            }
        }

        Ok(())
    }

    // async fn handle_transfer_event(&self, karma_sc: &KarmaSCInstance<AlloyWsProvider>, transfer_event: KarmaSC::Transfer) -> Result<(), HandleTransferError> {
    async fn handle_transfer_event<E: Into<AlloyContractError>, KSC: KarmaAmountExt<Error = E>, RLNSC: RLNRegister<Error = E> >(
        &self,
        karma_sc: &KSC,
        rln_sc: &RLNSC,
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
                        .map_err(|e| HandleTransferError::FetchBalanceOf(e.into()))?;
                    // Only register the user if he has a minimal amount of Karma token
                    balance >= self.minimal_amount
                }
            };

            if should_register {

                let id_commitment = self.user_db
                    .on_new_user(&to_address)
                    .map_err(HandleTransferError::Register)?;

                let id_co =
                    U256::from_le_slice(BigUint::from(id_commitment).to_bytes_le().as_slice());

                if let Err(e) = rln_sc.register_user(&to_address, id_co).await {
                    // Fail to register user on smart contract
                    // Remove the user in internal Db
                    if !self.user_db.remove_user(&to_address, false) {
                        // Fails if DB & SC are inconsistent
                        panic!("Unable to register user to SC and to remove it from DB...");
                    }

                    let e_ = RegisterSCError::from(e.into());
                    return Err(HandleTransferError::ScRegister(e_))
                }

            }
        }

        Ok(to_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    // std
    use std::sync::Arc;
    // third-party
    use alloy::primitives::address;
    use async_trait::async_trait;
    use parking_lot::RwLock;
    // internal
    use crate::epoch_service::{Epoch, EpochSlice};
    use crate::user_db_service::UserDbService;

    // const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");
    struct MockKarmaSc {}

    #[async_trait]
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
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let user_db_service = UserDbService::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            Default::default(),
            epoch_store,
            10.into(),
            Default::default(),
        )
        .unwrap();
        let user_db = user_db_service.get_user_db();

        assert!(user_db_service.get_user_db().get_user(&ADDR_2).is_none());

        let minimal_amount = U256::from(25);
        let registry = RegistryListener {
            rpc_url: "".to_string(),
            karma_sc_address: Default::default(),
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
