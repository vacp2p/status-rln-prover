// std
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
// third-party
use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use async_channel::Sender;
use bytesize::ByteSize;
use futures::TryFutureExt;
use http::Method;
use tokio::sync::{broadcast, mpsc};
use tonic::{
    Request, Response, Status, codegen::tokio_stream::wrappers::ReceiverStream, transport::Server,
};
use tonic_web::GrpcWebLayer;
use tower_http::cors::{Any, CorsLayer};
use tracing::debug;
// internal
use crate::error::{AppError, ProofGenerationStringError, RegisterError};
use crate::proof_generation::{ProofGenerationData, ProofSendingData};
use crate::tier::{KarmaAmount, TierLimit, TierName};
use crate::user_db_service::{KarmaAmountExt, UserDb, UserTierInfo};
use rln_proof::{RlnIdentifier, RlnUserIdentity};

pub mod prover_proto {

    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
    // for reflection service
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("prover_descriptor");
}
use prover_proto::{
    GetUserTierInfoReply, GetUserTierInfoRequest, RegisterUserReply, RegisterUserRequest,
    RegistrationStatus, RlnProof, RlnProofFilter, RlnProofReply, SendTransactionReply,
    SendTransactionRequest, SetTierLimitsReply, SetTierLimitsRequest, Tier, UserTierInfoError,
    UserTierInfoResult,
    get_user_tier_info_reply::Resp,
    rln_proof_reply::Resp as GetProofsResp,
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
const PROVER_SERVICE_MESSAGE_DECODING_MAX_SIZE: ByteSize = ByteSize::mib(5);
// Max size for Message (encoding, e.g., 5 Mb)
const PROVER_SERVICE_MESSAGE_ENCODING_MAX_SIZE: ByteSize = ByteSize::mib(5);
const PROVER_SPAM_LIMIT: u64 = 10_000;

#[derive(Debug)]
pub struct ProverService {
    proof_sender: Sender<ProofGenerationData>,
    user_db: UserDb,
    rln_identifier: Arc<RlnIdentifier>,
    spam_limit: u64,
    broadcast_channel: (
        broadcast::Sender<Result<ProofSendingData, ProofGenerationStringError>>,
        broadcast::Receiver<Result<ProofSendingData, ProofGenerationStringError>>,
    ),
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

        let user_id = if let Some(id) = self.user_db.get_user(&sender) {
            id.clone()
        } else {
            return Err(Status::not_found("Sender not registered"));
        };

        // Update the counter as soon as possible (should help to prevent spamming...)
        let counter = self.user_db.on_new_tx(&sender).unwrap_or_default();

        if req.transaction_hash.len() != 32 {
            return Err(Status::invalid_argument(
                "Invalid transaction hash (should be 32 bytes)",
            ));
        }

        let user_identity = RlnUserIdentity {
            secret_hash: user_id.secret_hash,
            commitment: user_id.commitment,
            user_limit: Fr::from(self.spam_limit),
        };

        // Inexpensive clone (behind Arc ptr)
        let rln_identifier = self.rln_identifier.clone();

        let proof_data = ProofGenerationData::from((
            user_identity,
            rln_identifier,
            counter.into(),
            sender,
            req.transaction_hash,
        ));

        // Send some data to one of the proof services
        /*
        self.proof_sender
            .send((user_identity, rln_identifier, counter.into()))
            .await
            .map_err(|e| Status::from_error(Box::new(e)))?;
        */
        self.proof_sender
            .send(proof_data)
            .await
            .map_err(|e| Status::from_error(Box::new(e)))?;

        let reply = SendTransactionReply { result: true };
        Ok(Response::new(reply))
    }

    async fn register_user(
        &self,
        request: Request<RegisterUserRequest>,
    ) -> Result<Response<RegisterUserReply>, Status> {
        debug!("register_user request: {:?}", request);

        let req = request.into_inner();
        let user = if let Some(user) = req.user {
            if let Ok(user) = Address::try_from(user.value.as_slice()) {
                user
            } else {
                return Err(Status::invalid_argument("Invalid sender address"));
            }
        } else {
            return Err(Status::invalid_argument("No sender address"));
        };

        let result = self.user_db.on_new_user(user);

        let status = match result {
            Ok(_) => RegistrationStatus::Success,
            Err(RegisterError::AlreadyRegistered(_a)) => RegistrationStatus::AlreadyRegistered,
            _ => RegistrationStatus::Failure,
        };

        let reply = RegisterUserReply {
            status: status.into(),
        };
        Ok(Response::new(reply))
    }

    type GetProofsStream = ReceiverStream<Result<RlnProofReply, Status>>;

    async fn get_proofs(
        &self,
        request: Request<RlnProofFilter>,
    ) -> Result<Response<Self::GetProofsStream>, Status> {
        debug!("get_proofs request: {:?}", request);
        // FIXME: channel size or unbounded channel?
        let (tx, rx) = mpsc::channel(100);
        let mut rx2 = self.broadcast_channel.0.subscribe();
        tokio::spawn(async move {
            // FIXME: Should we send the error here?
            while let Ok(Ok(data)) = rx2.recv().await {
                let rln_proof = RlnProof {
                    sender: data.tx_sender.to_vec(),
                    tx_hash: data.tx_hash,
                    proof: data.proof,
                };

                let resp = RlnProofReply {
                    resp: Some(GetProofsResp::Proof(rln_proof)),
                };

                if let Err(e) = tx.send(Ok(resp)).await {
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

        let req = request.into_inner();

        let user = if let Some(user) = req.user {
            if let Ok(user) = Address::try_from(user.value.as_slice()) {
                user
            } else {
                return Err(Status::invalid_argument("Invalid user address"));
            }
        } else {
            return Err(Status::invalid_argument("No user address"));
        };

        // TODO: SC call
        struct MockKarmaSc {}

        impl KarmaAmountExt for MockKarmaSc {
            async fn karma_amount(&self, _address: &Address) -> U256 {
                U256::from(10)
            }
        }
        let tier_info = self.user_db.user_tier_info(&user, MockKarmaSc {}).await;

        match tier_info {
            Ok(tier_info) => Ok(Response::new(GetUserTierInfoReply {
                resp: Some(Resp::Res(tier_info.into())),
            })),
            Err(e) => Ok(Response::new(GetUserTierInfoReply {
                resp: Some(Resp::Error(e.into())),
            })),
        }
    }

    async fn set_tier_limits(
        &self,
        request: Request<SetTierLimitsRequest>,
    ) -> Result<Response<SetTierLimitsReply>, Status> {
        debug!("request: {:?}", request);

        let request = request.into_inner();
        let tier_limits: Option<BTreeMap<KarmaAmount, (TierLimit, TierName)>> = request
            .karma_amounts
            .iter()
            .zip(request.tiers)
            .map(|(k, tier)| {
                let karma_amount = U256::try_from_le_slice(k.value.as_slice())?;
                let karma_amount = KarmaAmount::from(karma_amount);
                let tier_info = (
                    TierLimit::from(tier.quota),
                    TierName::from(tier.name.clone()),
                );
                Some((karma_amount, tier_info))
            })
            .collect();

        if tier_limits.is_none() {
            return Err(Status::invalid_argument("Invalid tier limits"));
        }

        // unwrap safe - just tested if None
        let reply = match self.user_db.on_new_tier_limits(tier_limits.unwrap()) {
            Ok(_) => SetTierLimitsReply {
                status: true,
                error: "".to_string(),
            },
            Err(e) => SetTierLimitsReply {
                status: false,
                error: e.to_string(),
            },
        };
        Ok(Response::new(reply))
    }
}

pub(crate) struct GrpcProverService {
    pub proof_sender: Sender<ProofGenerationData>,
    pub broadcast_channel: (
        broadcast::Sender<Result<ProofSendingData, ProofGenerationStringError>>,
        broadcast::Receiver<Result<ProofSendingData, ProofGenerationStringError>>,
    ),
    pub addr: SocketAddr,
    pub rln_identifier: RlnIdentifier,
    pub user_db: UserDb,
}

impl GrpcProverService {
    pub(crate) async fn serve(&self) -> Result<(), AppError> {
        let prover_service = ProverService {
            proof_sender: self.proof_sender.clone(),
            user_db: self.user_db.clone(),
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

/// UserTierInfo to UserTierInfoResult (Grpc message) conversion
impl From<UserTierInfo> for UserTierInfoResult {
    fn from(tier_info: UserTierInfo) -> Self {
        let mut res = UserTierInfoResult {
            current_epoch: tier_info.current_epoch.into(),
            current_epoch_slice: tier_info.current_epoch_slice.into(),
            tx_count: tier_info.epoch_tx_count,
            tier: None,
        };

        if tier_info.tier_name.is_some() && tier_info.tier_limit.is_some() {
            res.tier = Some(Tier {
                name: tier_info.tier_name.unwrap().into(),
                quota: tier_info.tier_limit.unwrap().into(),
            })
        }

        res
    }
}

/// UserTierInfoError to UserTierInfoError (Grpc message) conversion
impl From<crate::user_db_service::UserTierInfoError> for UserTierInfoError {
    fn from(value: crate::user_db_service::UserTierInfoError) -> Self {
        UserTierInfoError {
            message: value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::grpc_service::prover_proto::Address;
    use prost::Message;

    const MAX_ADDRESS_SIZE_BYTES: usize = 20;

    #[test]
    #[ignore]
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
