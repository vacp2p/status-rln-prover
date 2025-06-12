use crate::epoch_service::WaitUntilError;
use alloy::{
    primitives::Address,
    transports::{RpcError, TransportErrorKind},
};
use ark_serialize::SerializationError;
use rln::error::ProofError;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Tonic (grpc) error: {0}")]
    Tonic(#[from] tonic::transport::Error),
    #[error("Tonic reflection (grpc) error: {0}")]
    TonicReflection(#[from] tonic_reflection::server::Error),
    #[error("Rpc error 1: {0}")]
    RpcError(#[from] RpcError<RpcError<TransportErrorKind>>),
    #[error("Rpc transport error 2: {0}")]
    RpcTransportError(#[from] RpcError<TransportErrorKind>),
    #[error("Epoch service error: {0}")]
    EpochError(#[from] WaitUntilError),
    #[error(transparent)]
    RegistryError(#[from] HandleTransferError),
    #[error(transparent)]
    ContractError(#[from] alloy::contract::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ProofGenerationError {
    #[error("Proof generation failed: {0}")]
    Proof(#[from] ProofError),
    #[error("Proof serialization failed: {0}")]
    Serialization(#[from] SerializationError),
    #[error("Proof serialization failed: {0}")]
    SerializationWrite(#[from] std::io::Error),
    #[error(transparent)]
    MerkleProofError(#[from] GetMerkleTreeProofError),
}

/// Same as ProofGenerationError but can be Cloned (can be used in Tokio broadcast channels)
#[derive(thiserror::Error, Debug, Clone)]
pub enum ProofGenerationStringError {
    #[error("Proof generation failed: {0}")]
    Proof(String),
    #[error("Proof serialization failed: {0}")]
    Serialization(String),
    #[error("Proof serialization failed: {0}")]
    SerializationWrite(String),
    #[error(transparent)]
    MerkleProofError(#[from] GetMerkleTreeProofError),
}

impl From<ProofGenerationError> for ProofGenerationStringError {
    fn from(value: ProofGenerationError) -> Self {
        match value {
            ProofGenerationError::Proof(e) => ProofGenerationStringError::Proof(e.to_string()),
            ProofGenerationError::Serialization(e) => {
                ProofGenerationStringError::Serialization(e.to_string())
            }
            ProofGenerationError::SerializationWrite(e) => {
                ProofGenerationStringError::SerializationWrite(e.to_string())
            }
            ProofGenerationError::MerkleProofError(e) => {
                ProofGenerationStringError::MerkleProofError(e)
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RegisterError {
    #[error("User (address: {0:?}) has already been registered")]
    AlreadyRegistered(Address),
    #[error("Merkle tree error: {0}")]
    TreeError(String),
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum GetMerkleTreeProofError {
    #[error("User not registered")]
    NotRegistered,
    #[error("Merkle tree error: {0}")]
    TreeError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum HandleTransferError {
    #[error(transparent)]
    Register(#[from] RegisterError),
    #[error("Unable to query balance: {0}")]
    BalanceOf(#[from] alloy::contract::Error),
}
