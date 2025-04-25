use std::net::SocketAddr;

use futures::TryFutureExt;
use tokio::sync::mpsc;
use tonic::{
    Request, Response, Status, codegen::tokio_stream::wrappers::ReceiverStream, transport::Server,
};
use tracing::{
    debug,
    // error,
    // info
};

use crate::error::AppError;

pub mod prover_proto {

    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
    // for reflection service
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("prover_descriptor");
}
use prover_proto::{
    RlnProof, RlnProofFilter, SendTransactionReply, SendTransactionRequest,
    rln_prover_server::{RlnProver, RlnProverServer},
};

#[derive(Debug, Default)]
pub struct ProverService {}

#[tonic::async_trait]
impl RlnProver for ProverService {
    async fn send_transaction(
        &self,
        request: Request<SendTransactionRequest>,
    ) -> Result<Response<SendTransactionReply>, Status> {
        debug!("send_transaction request: {:?}", request);
        let req = request.into_inner();
        let sender = req.sender;
        // let tx_id = req.tx_id;

        let reply = SendTransactionReply {
            result: false,
            message: format!("User address: {} not registered", sender),
        };

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

        tokio::spawn(async move {
            // TODO: real proof
            debug!("Sending dummy rln proofs...");
            loop {
                let rln_proof = RlnProof {
                    sender: "0xAA".to_string(),
                    id_commitment: "1".to_string(),
                    proof: "__bytes__".to_string(),
                };
                // FIXME: no unwrap
                if let Err(e) = tx.send(Ok(rln_proof)).await {
                    debug!("Done: sending dummy rln proofs: {}", e);
                    break;
                };
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub(crate) struct GrpcProverService {
    addr: SocketAddr,
    // reflection_descriptor_set: &'a [u8],
}

impl GrpcProverService {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub(crate) async fn serve(&self) -> Result<(), AppError> {
        let prover_service = ProverService::default();
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
