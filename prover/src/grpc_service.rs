// std
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
// third-party
use alloy::primitives::Address;
use ark_bn254::Fr;
use async_channel::Sender;
use bytesize::ByteSize;
use futures::TryFutureExt;
use http::Method;
use tokio::sync::{
    broadcast,
    // broadcast::{Receiver, Sender},
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
use tonic_web::GrpcWebLayer;
use tower_http::cors::{Any, CorsLayer};
use tracing::{
    debug,
    // error,
    // info
};
// internal
use crate::error::{
    AppError,
    // RegistrationError
};

pub mod prover_proto {

    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
    // for reflection service
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("prover_descriptor");
}
use crate::grpc_service::prover_proto::{GetUserTierInfoReply, GetUserTierInfoRequest};
use crate::user_db::{TxRegistry, UserRegistry};
use prover_proto::{
    RegisterUserReply, RegisterUserRequest, RlnProof, RlnProofFilter, SendTransactionReply,
    SendTransactionRequest,
    rln_prover_server::{RlnProver, RlnProverServer},
};
use rln_proof::{
    // RlnData,
    RlnIdentifier,
    RlnUserIdentity,
    // ZerokitMerkleTree,
    // compute_rln_proof_and_values,
};

const PROVER_SERVICE_LIMIT_PER_CONNECTION: usize = 16;
// Timeout for all handlers of a request
const PROVER_SERVICE_GRPC_TIMEOUT: Duration = Duration::from_secs(30);
//
const PROVER_SERVICE_HTTP2_MAX_CONCURRENT_STREAM: u32 = 64;
// Http2 max frame size (e.g. 16 Kb)
const PROVER_SERVICE_HTTP2_MAX_FRAME_SIZE: ByteSize = ByteSize::kib(16);
// Max size for Message (decoding, e.g., 5 Mb)
const PROVER_SERVICE_MESSAGE_DECODING_MAX_SIZE: ByteSize = ByteSize::mib(5);
// Max size for Message (encoding, e.g., 5 Mb)
const PROVER_SERVICE_MESSAGE_ENCODING_MAX_SIZE: ByteSize = ByteSize::mib(5);
const PROVER_SPAM_LIMIT: u64 = 10_000;

#[derive(Debug)]
pub struct ProverService {
    proof_sender: Sender<(RlnUserIdentity, Arc<RlnIdentifier>, u64)>,
    user_registry: Arc<UserRegistry>,
    tx_registry: Arc<TxRegistry>,
    rln_identifier: Arc<RlnIdentifier>,
    spam_limit: u64,
    broadcast_channel: (broadcast::Sender<Vec<u8>>, broadcast::Receiver<Vec<u8>>),
}

#[tonic::async_trait]
impl RlnProver for ProverService {
    async fn send_transaction(
        &self,
        request: Request<SendTransactionRequest>,
    ) -> Result<Response<SendTransactionReply>, Status> {
        debug!("send_transaction request: {:?}", request);
        let req = request.into_inner();

        let sender = if let Some(sender) = req.sender {
            if let Ok(sender) = Address::try_from(sender.value.as_slice()) {
                sender
            } else {
                return Err(Status::invalid_argument("Invalid sender address"));
            }
        } else {
            return Err(Status::invalid_argument("No sender address"));
        };

        let user_id = if let Some(id) = self.user_registry.get(&sender) {
            id.clone()
        } else {
            return Err(Status::not_found("Sender not registered"));
        };

        // Update the counter as soon as possible (should help to prevent spamming...)
        let counter = self.tx_registry.incr_counter(&sender, None).unwrap_or(0);

        let user_identity = RlnUserIdentity {
            secret_hash: user_id.secret_hash,
            commitment: user_id.commitment,
            user_limit: Fr::from(self.spam_limit),
        };

        // Inexpensive clone (behind Arc ptr)
        let rln_identifier = self.rln_identifier.clone();

        // Send some data to one of the proof services
        self.proof_sender
            .send((user_identity, rln_identifier, counter))
            .await
            .map_err(|e| Status::from_error(Box::new(e)))?;

        let reply = SendTransactionReply { result: true };
        Ok(Response::new(reply))
    }

    async fn register_user(
        &self,
        _request: Request<RegisterUserRequest>,
    ) -> Result<Response<RegisterUserReply>, Status> {
        let reply = RegisterUserReply { status: 0 };
        Ok(Response::new(reply))
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

    async fn get_user_tier_info(
        &self,
        request: Request<GetUserTierInfoRequest>,
    ) -> Result<Response<GetUserTierInfoReply>, Status> {
        debug!("request: {:?}", request);
        todo!()
    }
}

pub(crate) struct GrpcProverService {
    pub proof_sender: Sender<(RlnUserIdentity, Arc<RlnIdentifier>, u64)>,
    pub broadcast_channel: (broadcast::Sender<Vec<u8>>, broadcast::Receiver<Vec<u8>>),
    pub addr: SocketAddr,
    pub rln_identifier: RlnIdentifier,
    pub user_registry: Arc<UserRegistry>,
    pub tx_registry: Arc<TxRegistry>,
}

impl GrpcProverService {
    /*
    pub(crate) fn new(
        proof_sender: Sender<(RlnUserIdentity, Arc<RlnIdentifier>, u64)>,
        broadcast_channel: (broadcast::Sender<Vec<u8>>, broadcast::Receiver<Vec<u8>>),
        addr: SocketAddr,
        rln_identifier: RlnIdentifier,

    ) -> Self {
        Self {
            proof_sender,
            broadcast_channel,
            addr,
            rln_identifier,
            user_registry: Arc::new(Default::default()),
            tx_registry: Arc::new(Default::default()),
        }
    }
    */

    pub(crate) async fn serve(&self) -> Result<(), AppError> {
        let prover_service = ProverService {
            proof_sender: self.proof_sender.clone(),
            user_registry: self.user_registry.clone(),
            tx_registry: self.tx_registry.clone(),
            rln_identifier: Arc::new(self.rln_identifier.clone()),
            spam_limit: PROVER_SPAM_LIMIT,
            broadcast_channel: (
                self.broadcast_channel.0.clone(),
                self.broadcast_channel.0.subscribe(),
            ),
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

        // CORS
        let cors = CorsLayer::new()
            // Allow `GET`, `POST` and `OPTIONS` when accessing the resource
            .allow_methods([
                Method::GET,
                // http POST && OPTIONS not required for grpc-web
                // Method::POST,
                // Method::OPTIONS
            ])
            // Allow requests from any origin
            // FIXME: config?
            .allow_origin(Any)
            .allow_headers(Any);

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
            // http 1 layer required for GrpcWebLayer
            .accept_http1(true)
            // services
            .layer(cors)
            .layer(GrpcWebLayer::new())
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
