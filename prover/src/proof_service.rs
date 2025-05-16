use std::io::{Cursor, Write};
use std::sync::Arc;
// third-party
use ark_bn254::Fr;
use ark_serialize::{CanonicalSerialize, SerializationError};
use async_channel::Receiver;
use rln::hashers::{hash_to_field, poseidon_hash};
use rln::pm_tree_adapter::PmTree;
use rln::protocol::{ProofError, serialize_proof_values};
use tracing::debug;
// internal
use crate::error::AppError;
use rln_proof::{
    RlnData, RlnIdentifier, RlnUserIdentity, ZerokitMerkleTree, compute_rln_proof_and_values,
};

#[derive(thiserror::Error, Debug)]
enum ProofGenerationError {
    #[error("Proof generation failed: {0}")]
    Proof(#[from] ProofError),
    #[error("Proof serialization failed: {0}")]
    Serialization(#[from] SerializationError),
    #[error("Proof serialization failed: {0}")]
    SerializationWrite(#[from] std::io::Error),
    #[error("Error: {0}")]
    Misc(String),
}

#[derive(Debug)]
pub struct ProofService {
    receiver: Receiver<(RlnUserIdentity, Arc<RlnIdentifier>, u64)>,
    broadcast_sender: tokio::sync::broadcast::Sender<Vec<u8>>,
}

impl ProofService {
    pub(crate) fn new(
        receiver: Receiver<(RlnUserIdentity, Arc<RlnIdentifier>, u64)>,
        broadcast_sender: tokio::sync::broadcast::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            receiver,
            broadcast_sender,
        }
    }

    pub(crate) async fn serve(&self) -> Result<(), AppError> {
        loop {
            let received = self.receiver.recv().await;

            if let Err(e) = received {
                debug!("Stopping proof generation service: {}", e);
                break;
            }
            let (user_identity, rln_identifier, counter) = received.unwrap();

            // Move to a task (as generating the proof can take quite some time)
            let blocking_task = tokio::task::spawn_blocking(move || {
                let rln_data = RlnData {
                    message_id: Fr::from(counter),
                    // TODO: tx hash to field
                    data: hash_to_field(b"RLN is awesome"),
                };
                // FIXME: track/update epoch
                let epoch = hash_to_field(b"Today at noon, this year");

                // FIXME: maintain tree in Prover or query RLN Reg SC ?
                // Merkle tree
                let tree_height = 20;
                let mut tree = PmTree::new(tree_height, Fr::from(0), Default::default())
                    .map_err(|e| ProofGenerationError::Misc(e.to_string()))?;

                // let mut tree = OptimalMerkleTree::new(tree_height, Fr::from(0), Default::default()).unwrap();
                let rate_commit =
                    poseidon_hash(&[user_identity.commitment, user_identity.user_limit]);
                tree.set(0, rate_commit)
                    .map_err(|e| ProofGenerationError::Misc(e.to_string()))?;
                let merkle_proof = tree
                    .proof(0)
                    .map_err(|e| ProofGenerationError::Misc(e.to_string()))?;

                let (proof, proof_values) = compute_rln_proof_and_values(
                    &user_identity,
                    &rln_identifier,
                    rln_data,
                    epoch,
                    &merkle_proof,
                )
                .map_err(ProofGenerationError::Proof)?;

                // Serialize proof
                // FIXME: proof size?
                let mut output_buffer = Cursor::new(Vec::with_capacity(512));
                proof
                    .serialize_compressed(&mut output_buffer)
                    .map_err(ProofGenerationError::Serialization)?;
                output_buffer
                    .write_all(&serialize_proof_values(&proof_values))
                    .map_err(ProofGenerationError::SerializationWrite)?;

                Ok::<Vec<u8>, ProofGenerationError>(output_buffer.into_inner())
            });

            let result = blocking_task.await;
            // if let Err(e) = result {
            //     return Err(Status::from_error(Box::new(e)));
            // }
            // blocking_task returns Result<Result<Vec<u8>, _>>
            // Result (1st) is a JoinError (and should not happen)
            // Result (2nd) is a ProofGenerationError
            let result = result.unwrap().unwrap();
            // TODO: no unwrap()
            // FIXME: send proof + other info
            self.broadcast_sender.send(result).unwrap();
        }

        Ok(())
    }
}
