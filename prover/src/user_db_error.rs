use crate::tier::ValidateTierLimitsError;
use alloy::primitives::Address;
use std::num::TryFromIntError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum UserDbOpenError {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] TryFromIntError),
}

#[derive(thiserror::Error, Debug)]
pub enum RegisterError {
    #[error("User (address: {0:?}) has already been registered")]
    AlreadyRegistered(Address),
    #[error(transparent)]
    Db(#[from] rocksdb::Error),
    #[error("Merkle tree error: {0}")]
    TreeError(String),
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TxCounterError {
    #[error("User (address: {0:?}) is not registered")]
    NotRegistered(Address),
    #[error(transparent)]
    Db(#[from] rocksdb::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SetTierLimitsError {
    #[error(transparent)]
    Validate(#[from] ValidateTierLimitsError),
    #[error("Updating an invalid tier index")]
    InvalidUpdateTierIndex,
    #[error(transparent)]
    Db(#[from] rocksdb::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum UserTierInfoError<E: std::error::Error> {
    #[error("User {0} not registered")]
    NotRegistered(Address),
    #[error(transparent)]
    Contract(E),
    #[error(transparent)]
    TxCounter(#[from] TxCounterError),
    #[error(transparent)]
    Db(#[from] rocksdb::Error),
}
