// std
use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
// third-party
use alloy::primitives::Address;
use ark_bn254::Fr;
use futures::TryFutureExt;
use parking_lot::RwLock;
use rln::{
    hashers::{hash_to_field, poseidon_hash},
    protocol::prepare_prove_input,
    public::RLN,
};
use serde_json::json;
use tokio::sync::{
    broadcast,
    broadcast::{Receiver, Sender},
    mpsc,
};
use tonic::{
    Request, Response, Status, codegen::tokio_stream::wrappers::ReceiverStream, transport::Server,
};
use tracing::{
    debug,
    // error,
    // info
};
// internal
use crate::error::{AppError, RegistrationError};

pub mod prover_proto {

    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
    // for reflection service
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("prover_descriptor");
}
use prover_proto::{
    RegisterUserReply, RegisterUserRequest, RlnProof, RlnProofFilter, SendTransactionReply,
    SendTransactionRequest,
    rln_prover_server::{RlnProver, RlnProverServer},
};

#[derive(Debug)]
pub struct ProverService {
    user_registered: RwLock<HashMap<Address, (Fr, Fr)>>,
    broadcast_channel: (Sender<Vec<u8>>, Receiver<Vec<u8>>),
}

#[tonic::async_trait]
impl RlnProver for ProverService {
    async fn send_transaction(
        &self,
        request: Request<SendTransactionRequest>,
    ) -> Result<Response<SendTransactionReply>, Status> {
        debug!("send_transaction request: {:?}", request);
        let req = request.into_inner();
        let sender = req.sender;

        let id = if let Some(sender) = sender {
            let guard = self.user_registered.read();
            if let Ok(sender_) = Address::try_from(sender.value.as_slice()) {
                if let Some(id) = guard.get(&sender_) {
                    Ok(*id)
                } else {
                    Err(RegistrationError::NotFound(sender_))
                }
            } else {
                Err(RegistrationError::InvalidAddress(sender.value.to_vec()))
            }
        } else {
            Err(RegistrationError::NoSender)
        };

        let reply = match id {
            Ok(id) => {
                let id_secret_hash = id.0;
                let _id_commitment = id.1;

                // TODO/FIXME: blocking code
                {
                    // FIXME
                    let tree_height = 20;
                    let input = Cursor::new(json!({}).to_string());
                    let mut rln = RLN::new(tree_height, input).unwrap();

                    // FIXME
                    let message_id = Fr::from(1);
                    let id_index = 10;
                    let user_message_limit = Fr::from(10);
                    let rln_identifier = hash_to_field(b"test-rln-identifier");
                    let epoch = hash_to_field(b"Today at noon, this year");
                    let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);
                    let signal = b"RLN is awesome";

                    let prove_input = prepare_prove_input(
                        id_secret_hash,
                        id_index,
                        user_message_limit,
                        message_id,
                        external_nullifier,
                        signal,
                    );

                    let mut input_buffer = Cursor::new(prove_input);
                    let mut output_buffer = Cursor::new(Vec::<u8>::new());
                    rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
                        .unwrap();

                    self.broadcast_channel
                        .0
                        .send(output_buffer.into_inner())
                        .unwrap();
                }

                SendTransactionReply {
                    result: true,
                    message: "".to_string(),
                }
            }
            Err(e) => SendTransactionReply {
                result: false,
                message: e.to_string(),
            },
        };

        Ok(Response::new(reply))
    }

    async fn register_user(
        &self,
        _request: Request<RegisterUserRequest>,
    ) -> Result<Response<RegisterUserReply>, Status> {
        todo!()
    }

    type GetProofsStream = ReceiverStream<Result<RlnProof, Status>>;

    async fn get_proofs(
        &self,
        request: Request<RlnProofFilter>,
    ) -> Result<Response<Self::GetProofsStream>, Status> {
        debug!("get_proofs request: {:?}", request);
        // FIXME: channel size or unbounded channel?
        let (tx, rx) = mpsc::channel(100);
        let mut rx2 = self.broadcast_channel.0.subscribe();
        tokio::spawn(async move {
            while let Ok(data) = rx2.recv().await {
                let rln_proof = RlnProof {
                    sender: "0xAA".to_string(),
                    id_commitment: "1".to_string(),
                    proof: data,
                };
                if let Err(e) = tx.send(Ok(rln_proof)).await {
                    debug!("Done: sending dummy rln proofs: {}", e);
                    break;
                };
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub(crate) struct GrpcProverService {
    addr: SocketAddr,
}

impl GrpcProverService {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub(crate) async fn serve(&self) -> Result<(), AppError> {
        let (tx, rx) = broadcast::channel(2);
        let prover_service = ProverService {
            user_registered: Default::default(),
            broadcast_channel: (tx, rx),
        };
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(prover_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        Server::builder()
            .add_service(reflection_service)
            .add_service(RlnProverServer::new(prover_service))
            .serve(self.addr)
            .map_err(AppError::from)
            .await
    }
}
