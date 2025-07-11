use alloy::primitives::Address;
use std::str::FromStr;
use tonic::Response;

pub mod prover_proto {

    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
}

use prover_proto::{
    Address as GrpcAddress, RegisterUserReply, RegisterUserRequest,
    // RegistrationStatus,
    rln_prover_client::RlnProverClient,
};

#[tokio::main]
async fn main() {
    // FIXME: clap
    let url = "http://127.0.0.1:42942";
    let addr = "0xb20a608c624Ca5003905aA834De7156C68b2E1d0";

    let addr = Address::from_str(addr).unwrap();

    let grpc_addr = GrpcAddress {
        value: addr.to_vec(),
    };

    let mut client = RlnProverClient::connect(url).await.unwrap();
    let request_0 = RegisterUserRequest {
        user: Some(grpc_addr),
    };
    let request = tonic::Request::new(request_0);
    let response: Response<RegisterUserReply> = client.register_user(request).await.unwrap();

    println!(
        "RegisterUSerReply status: {:?}",
        response.into_inner().status
    );
}
