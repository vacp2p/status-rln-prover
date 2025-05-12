// std
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::Duration;
// third-party
use alloy::primitives::Address;
use ark_bn254::Fr;
use bytesize::ByteSize;
use futures::TryFutureExt;
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
    Request,
    Response,
    Status,
    codegen::tokio_stream::wrappers::ReceiverStream,
    transport::Server,
    // codec::CompressionEncoding
};
use tracing::{
    debug,
    // error,
    // info
};
// internal
use crate::{
    error::{AppError, RegistrationError},
    registry::UserRegistry,
};

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

const PROVER_SERVICE_LIMIT_PER_CONNECTION: usize = 16;
// Timeout for all handlers of a request
const PROVER_SERVICE_GRPC_TIMEOUT: Duration = Duration::from_secs(30);
//
const PROVER_SERVICE_HTTP2_MAX_CONCURRENT_STREAM: u32 = 64;
// Http2 max frame size (e.g. 16 Kb)
const PROVER_SERVICE_HTTP2_MAX_FRAME_SIZE: ByteSize = ByteSize::kib(16);
// Max size for Message (decoding, e.g., 5 Mb)
// const PROVER_SERVICE_MESSAGE_DECODING_MAX_SIZE: usize = 1024 * 1024 * 5;
const PROVER_SERVICE_MESSAGE_DECODING_MAX_SIZE: ByteSize = ByteSize::mib(5);
// Max size for Message (encoding, e.g., 5 Mb)
const PROVER_SERVICE_MESSAGE_ENCODING_MAX_SIZE: ByteSize = ByteSize::mib(5);

#[derive(Debug)]
pub struct ProverService {
    registry: UserRegistry,
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
            if let Ok(sender_) = Address::try_from(sender.value.as_slice()) {
                if let Some(id) = self.registry.get(&sender_) {
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
            registry: Default::default(),
            broadcast_channel: (tx, rx),
        };

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(prover_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        let r = RlnProverServer::new(prover_service)
            .max_decoding_message_size(PROVER_SERVICE_MESSAGE_DECODING_MAX_SIZE.as_u64() as usize)
            .max_encoding_message_size(PROVER_SERVICE_MESSAGE_ENCODING_MAX_SIZE.as_u64() as usize)
            // TODO: perf?
            //.accept_compressed(CompressionEncoding::Gzip)
            //.send_compressed(CompressionEncoding::Gzip)
            ;

        Server::builder()
            // service protection && limits
            // limits: connection
            .concurrency_limit_per_connection(PROVER_SERVICE_LIMIT_PER_CONNECTION)
            .timeout(PROVER_SERVICE_GRPC_TIMEOUT)
            // limits : http2
            .max_concurrent_streams(PROVER_SERVICE_HTTP2_MAX_CONCURRENT_STREAM)
            .max_frame_size(PROVER_SERVICE_HTTP2_MAX_FRAME_SIZE.as_u64() as u32)
            // perf: tcp
            .tcp_nodelay(true)
            // No http 1
            .accept_http1(false)
            // services
            .add_service(reflection_service)
            .add_service(r)
            .serve(self.addr)
            .map_err(AppError::from)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::grpc_service::prover_proto::Address;
    use prost::Message;
    // use crate::proto::prover::{Address}; // Adjust the import path as needed

    const MAX_ADDRESS_SIZE_BYTES: usize = 20;

    #[test]
    #[should_panic]
    fn test_address_size_limit() {
        // Check if an invalid address can be encoded (as Address grpc type)

        let invalid_address = vec![0; MAX_ADDRESS_SIZE_BYTES + 1];

        let addr = Address {
            value: invalid_address,
        };
        let mut addr_encoded = vec![];
        addr.encode(&mut addr_encoded).unwrap();

        let _addr_decoded = Address::decode(&*addr_encoded).unwrap();
    }
}
