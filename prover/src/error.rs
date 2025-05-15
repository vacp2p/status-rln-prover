use alloy::{
    primitives::Address,
    transports::{RpcError, TransportErrorKind},
};

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Tonic (grpc) error: {0}")]
    Tonic(#[from] tonic::transport::Error),
    #[error("Tonic reflection (grpc) error: {0}")]
    TonicReflection(#[from] tonic_reflection::server::Error),
    #[error("SC error 1: {0}")]
    Alloy(#[from] RpcError<RpcError<TransportErrorKind>>),
    #[error("SC error 2: {0}")]
    Alloy2(#[from] RpcError<TransportErrorKind>),
}

#[derive(thiserror::Error, Debug)]
pub enum RegistrationError {
    #[error("Transaction has no sender address")]
    NoSender,
    #[error("Transaction sender address is invalid: {0:?}")]
    InvalidAddress(Vec<u8>),
    #[error("Cannot find id_commitment for address: {0:?}")]
    NotFound(Address),
}
