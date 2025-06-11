use alloy::primitives::{Address, U256};
use async_trait::async_trait;
use log::debug;
use crate::{KarmaAmountExt, RLNRegister};

pub struct MockKarmaSc {}

#[async_trait]
impl KarmaAmountExt for MockKarmaSc {
    type Error = alloy::contract::Error;

    async fn karma_amount(&self, _address: &Address) -> Result<U256, Self::Error> {
        Ok(U256::from(10))
    }
}

pub struct MockKarmaRLNSc {}

#[async_trait]
impl RLNRegister for MockKarmaRLNSc {
    type Error = alloy::contract::Error;

    async fn register(&self, identity_commitment: U256) -> Result<(), Self::Error> {
        debug!("Register user with identity_commitment: {:?}", identity_commitment);
        Ok(())
    }
}
