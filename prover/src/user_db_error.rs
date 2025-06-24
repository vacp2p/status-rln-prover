use std::num::TryFromIntError;
use ark_serialize::SerializationError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum UserDbOpenError {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] TryFromIntError),
}
