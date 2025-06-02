use std::io::{Cursor, Write};
use std::sync::Arc;
// third-party
use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use async_channel::Receiver;
use parking_lot::RwLock;
use rln::hashers::hash_to_field;
use rln::protocol::serialize_proof_values;
use tracing::{debug, info};
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::{AppError, ProofGenerationError};
use crate::proof_generation::{ProofGenerationData, ProofSendingData};
use crate::user_db_service::UserDb;
use rln_proof::{RlnData, compute_rln_proof_and_values};

/// A service to generate a RLN proof (and then to broadcast it)
pub struct ProofService {
    receiver: Receiver<ProofGenerationData>,
    broadcast_sender: tokio::sync::broadcast::Sender<ProofSendingData>,
    current_epoch: Arc<RwLock<(Epoch, EpochSlice)>>,
    user_db: UserDb,
}

impl ProofService {
    pub(crate) fn new(
        receiver: Receiver<ProofGenerationData>,
        broadcast_sender: tokio::sync::broadcast::Sender<ProofSendingData>,
        current_epoch: Arc<RwLock<(Epoch, EpochSlice)>>,
        user_db: UserDb,
    ) -> Self {
        Self {
            receiver,
            broadcast_sender,
            current_epoch,
            user_db,
        }
    }

    pub(crate) async fn serve(&self) -> Result<(), AppError> {
        loop {
            let received = self.receiver.recv().await;

            if let Err(e) = received {
                info!("Stopping proof generation service: {}", e);
                break;
            }

            let proof_generation_data = received.unwrap();

            let (current_epoch, current_epoch_slice) = *self.current_epoch.read();
            let user_db = self.user_db.clone();
            let proof_generation_data_ = proof_generation_data.clone();

            // Move to a task (as generating the proof can take quite some time)
            let blocking_task = tokio::task::spawn_blocking(move || {
                let rln_data = RlnData {
                    message_id: Fr::from(proof_generation_data.tx_counter),
                    data: hash_to_field(proof_generation_data.tx_hash.as_slice()),
                };

                let epoch_bytes = {
                    let mut v = i64::from(current_epoch).to_be_bytes().to_vec();
                    v.extend(i64::from(current_epoch_slice).to_be_bytes());
                    v
                };
                let epoch = hash_to_field(epoch_bytes.as_slice());

                let merkle_proof = user_db.get_merkle_proof(&proof_generation_data.tx_sender)?;

                let (proof, proof_values) = compute_rln_proof_and_values(
                    &proof_generation_data.user_identity,
                    &proof_generation_data.rln_identifier,
                    rln_data,
                    epoch,
                    &merkle_proof,
                )
                .map_err(ProofGenerationError::Proof)?;

                debug!("proof: {:?}", proof);
                debug!("proof_values: {:?}", proof_values);

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
            // Result (1st) is a JoinError (and should not happen)
            // Result (2nd) is a ProofGenerationError
            let result = result
                .unwrap()
                .unwrap(); // TODO: broadcast error so the Verifier will not wait ?
            
            let proof_sending_data = ProofSendingData {
                tx_hash: proof_generation_data_.tx_hash,
                tx_sender: proof_generation_data_.tx_sender,
                proof: result,
            };

            if let Err(e) = self.broadcast_sender.send(proof_sending_data) {
                info!("Stopping proof generation service: {}", e);
                break;
            };
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // third-party
    use alloy::primitives::{Address, address};
    use ark_groth16::{Proof as ArkProof, VerifyingKey};
    use ark_serialize::CanonicalDeserialize;
    use claims::assert_matches;
    use futures::TryFutureExt;
    use rln::circuit::{Curve, zkey_from_folder};
    use tokio::sync::broadcast;
    use tracing::info;
    // third-party: zerokit
    use rln::protocol::{deserialize_proof_values, verify_proof};
    // internal
    use crate::user_db_service::UserDbService;
    use rln_proof::RlnIdentifier;

    const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");

    const TX_HASH_1: [u8; 32] = [0x01; 32];

    #[derive(thiserror::Error, Debug)]
    enum AppErrorExt {
        #[error("AppError: {0}")]
        AppError(#[from] AppError),
        #[error("Future timeout")]
        Elapsed,
        #[error("Proof verification failed")]
        ProofVerification,
        #[error("Exiting...")]
        Exit,
    }

    async fn proof_sender(
        proof_tx: &mut async_channel::Sender<ProofGenerationData>,
        rln_identifier: Arc<RlnIdentifier>,
        user_db: &UserDb,
    ) -> Result<(), AppErrorExt> {
        // used by test_proof_generation unit test

        debug!("Starting proof sender...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        debug!("Sending proof...");
        proof_tx
            .send(ProofGenerationData {
                user_identity: user_db.get_user(&ADDR_1).unwrap(),
                rln_identifier,
                tx_counter: 0,
                tx_sender: ADDR_1,
                tx_hash: TX_HASH_1.to_vec(),
            })
            .await
            .unwrap();
        debug!("Sending proof done");
        // tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        Ok::<(), AppErrorExt>(())
    }

    async fn proof_verifier(
        broadcast_receiver: &mut broadcast::Receiver<ProofSendingData>,
        verifying_key: &VerifyingKey<Curve>,
    ) -> Result<(), AppErrorExt> {
        // used by test_proof_generation unit test

        debug!("Starting broadcast receiver...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let res =
            tokio::time::timeout(std::time::Duration::from_secs(5), broadcast_receiver.recv())
                .await
                .map_err(|_e| AppErrorExt::Elapsed)?;
        debug!("res: {:?}", res);

        let res = res.unwrap();
        let mut proof_cursor = Cursor::new(&res.proof);
        debug!("proof cursor: {:?}", proof_cursor);
        let proof = ArkProof::deserialize_compressed(&mut proof_cursor).unwrap();
        let position = proof_cursor.position() as usize;
        let proof_cursor_2 = &proof_cursor.get_ref().as_slice()[position..];
        let (proof_values, _) = deserialize_proof_values(proof_cursor_2);
        debug!("[proof verifier] proof: {:?}", proof);
        debug!("[proof verifier] proof_values: {:?}", proof_values);

        let verified = verify_proof(verifying_key, &proof, &proof_values)
            .map_err(|_e| AppErrorExt::ProofVerification)?;

        debug!("verified: {:?}", verified);

        // Exit after receiving one proof
        Err::<(), AppErrorExt>(AppErrorExt::Exit)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_proof_generation() {
        // Queues
        let (broadcast_sender, _broadcast_receiver) = tokio::sync::broadcast::channel(2);
        let mut broadcast_receiver = broadcast_sender.subscribe();
        let (mut proof_tx, proof_rx) = async_channel::unbounded();

        // Epoch
        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));

        // User db
        let user_db_service = UserDbService::new(Default::default(), epoch_store.clone());
        let user_db = user_db_service.get_user_db();
        user_db.on_new_user(ADDR_1).unwrap();
        user_db.on_new_user(ADDR_2).unwrap();

        let rln_identifier = Arc::new(RlnIdentifier::new(b"foo bar baz"));

        // Proof service
        let proof_service =
            ProofService::new(proof_rx, broadcast_sender, epoch_store, user_db.clone());

        // Verification
        let proving_key = zkey_from_folder();
        let verification_key = &proving_key.0.vk;

        info!("Starting...");
        println!("Starting...");
        let res = tokio::try_join!(
            proof_service.serve().map_err(AppErrorExt::AppError),
            proof_verifier(&mut broadcast_receiver, verification_key),
            proof_sender(&mut proof_tx, rln_identifier.clone(), &user_db),
        );

        // Everything ok if ... TODO TODO
        assert_matches!(res, Err(AppErrorExt::Exit));
    }
}
