use alloy::transports::{RpcError, TransportErrorKind};

#[derive(thiserror::Error, Debug)]
pub enum SmartContractError {
    // Common transport and contract errors (used by all smart contracts)
    #[error("RPC transport error: {0}")]
    RpcTransportError(#[from] RpcError<TransportErrorKind>),
    #[error(transparent)]
    Alloy(#[from] alloy::contract::Error),
    #[error("Pending transaction error: {0}")]
    PendingTransactionError(#[from] alloy::providers::PendingTransactionError),

    // Authentication errors (used by RLN SC and Karma SC)
    #[error("Private key cannot be empty")]
    EmptyPrivateKey,
    #[error("Unable to connect with signer: {0}")]
    SignerConnectionError(String),

    // Karma Tiers specific errors
    #[error("Tier count too high (exceeds u8)")]
    TierCountTooHigh,
}
