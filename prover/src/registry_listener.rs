// third-party
use alloy::{
    contract::Error as AlloyContractError,
    primitives::{Address, U256},
    providers::Provider,
    sol_types::SolEvent,
};
use num_bigint::BigUint;
use tonic::codegen::tokio_stream::StreamExt;
use tracing::{debug, error, info};
// internal
use crate::error::{AppError, HandleTransferError, RegisterSCError};
use crate::user_db::UserDb;
use crate::user_db_error::RegisterError;
use smart_contract::{KarmaAmountExt, KarmaRLNSC, KarmaSC, RLNRegister};

pub(crate) struct RegistryListener {
    karma_sc_address: Address,
    rln_sc_address: Address,
    user_db: UserDb,
    minimal_amount: U256,
}

impl RegistryListener {
    pub(crate) fn new(
        karma_sc_address: Address,
        rln_sc_address: Address,
        user_db: UserDb,
        minimal_amount: U256,
    ) -> Self {
        Self {
            karma_sc_address,
            rln_sc_address,
            user_db,
            minimal_amount,
        }
    }

    /// Listen to Smart Contract specified events
    pub(crate) async fn listen<P: Provider + Clone, PS: Provider>(
        &self,
        provider: P,
        provider_with_signer: PS,
    ) -> Result<(), AppError> {
        // let provider = self.setup_provider_ws().await.map_err(AppError::from)?;
        let karma_sc = KarmaSC::new(self.karma_sc_address, provider.clone());

        // let provider_with_signer = self.setup_provider_with_signer(self.private_key.clone())
        //     .await
        //     .map_err(AppError::from)?;
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
                    match self
                        .handle_transfer_event(&karma_sc, &rln_sc, transfer_event)
                        .await
                    {
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

    /// Handle transfer event from Karma smart contract
    ///
    /// Handle 'Transfer' event but filter on Transfer event from a _mint call.
    /// As we can see here: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/53bb34057ed97ea9b36d550f1c2c413ef5b6c6bb/contracts/token/ERC20/ERC20.sol#L214
    /// _mint function emits a Transfer event (with from_adress set to 0x0). UserDb (on disk) is updated
    /// as well as RLN Smart contract.
    /// Can panic if RLN Smart contract registration fails, and UserDb remove fails too (but this should
    /// never happen)
    async fn handle_transfer_event<
        E: Into<AlloyContractError>,
        KSC: KarmaAmountExt<Error = E>,
        RLNSC: RLNRegister<Error = E>,
    >(
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
                let id_commitment = self
                    .user_db
                    .on_new_user(&to_address)
                    .map_err(HandleTransferError::Register);

                // Don't stop the registry_listener if the user_db is full
                // Prover will still be functional
                if let Err(HandleTransferError::Register(RegisterError::TooManyUsers)) =
                    id_commitment
                {
                    error!("Cannot register a new user: {:?}", id_commitment);
                }

                let id_commitment = id_commitment?;

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
                    return Err(HandleTransferError::ScRegister(e_));
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

    // Mock Karma Sc

    struct MockKarmaSc {}

    #[async_trait]
    impl KarmaAmountExt for MockKarmaSc {
        type Error = AlloyContractError;
        async fn karma_amount(&self, _address: &Address) -> Result<U256, Self::Error> {
            Ok(U256::from(10))
        }
    }

    // Mock RLN Sc
    struct MockRLNSc {}

    #[async_trait]
    impl RLNRegister for MockRLNSc {
        type Error = AlloyContractError;

        async fn register_user(
            &self,
            _address: &Address,
            _identity_commitment: U256,
        ) -> Result<(), Self::Error> {
            // println!("Registering user: {} with identity commitment: {}...", address, identity_commitment);
            Ok(())
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
            rln_sc_address: Default::default(),
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
        let rln_sc = MockRLNSc {};
        registry
            .handle_transfer_event(&karma_sc, &rln_sc, transfer)
            .await
            .unwrap();

        assert!(user_db_service.get_user_db().get_user(&ADDR_2).is_some());
    }
}
