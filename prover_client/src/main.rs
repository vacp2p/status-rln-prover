use std::net::IpAddr;
use alloy::primitives::{Address, U256};
use std::str::FromStr;
use clap::{Args, Parser, Subcommand};
use tonic::Response;

pub mod prover_proto {
    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
}

use prover_proto::{
    Address as GrpcAddress, RegisterUserReply, RegisterUserRequest,
    SendTransactionRequest, SendTransactionReply,
    // RegistrationStatus,
    rln_prover_client::RlnProverClient,
    U256 as GrpcU256, Wei as GrpcWei,
};
use crate::prover_proto::RegistrationStatus;

#[derive(Debug, Clone, Parser)]
#[command(about = "RLN prover client", long_about = None)]
pub struct AppArgs {
    #[arg(short = 'i', long = "ip", default_value = "::1", help = "Service ip")]
    pub ip: IpAddr,
    #[arg(
        short = 'p',
        long = "port",
        default_value = "50051",
        help = "Service port"
    )]
    pub port: u16,
    #[arg(
        short = 'a',
        long = "address",
        default_value = "0xb20a608c624Ca5003905aA834De7156C68b2E1d0",
        help = "User address"
    )]
    pub address: Address,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, PartialEq, Subcommand)]
pub(crate) enum Commands {
    #[command(about = "Register a new user")]
    RegisterUser, // (RegisterUserArgs),
    #[command(about = "Send a transaction")]
    SendTransaction(SendTransactionArgs),
}

#[derive(Debug, Clone, PartialEq, Args)]
pub struct SendTransactionArgs {
    #[arg(short = 't', long = "tx-hash", help = "Tx hash")]
    tx_hash: String,
}

#[tokio::main]
async fn main() {

    let app_args = AppArgs::parse();

    let url = format!("http://{}:{}", app_args.ip, app_args.port);
    println!("url: {url}");
    let mut client = RlnProverClient::connect(url).await.unwrap();
    let grpc_addr = GrpcAddress {
        value: app_args.address.to_vec(),
    };

    match app_args.command {
        Commands::RegisterUser => {

            let request_0 = RegisterUserRequest {
                user: Some(grpc_addr),
            };
            let request = tonic::Request::new(request_0);
            let response: Response<RegisterUserReply> = client.register_user(request).await.unwrap();

            println!(
                "RegisterUSerReply status: {:?}",
                RegistrationStatus::try_from(response.into_inner().status)
            );
        }
        Commands::SendTransaction(_send_transaction_args) => {
            // TODO: from args
            let chain_id = GrpcU256 {
                // FIXME: LE or BE?
                value: U256::from(1).to_le_bytes::<32>().to_vec(),
            };
            // TODO: from args
            let wei = GrpcWei {
                // FIXME: LE or BE?
                value: U256::from(1000).to_le_bytes::<32>().to_vec(),
            };
            // TODO: from args
            let tx_hash = U256::from(42).to_le_bytes::<32>().to_vec();

            let request_0 = SendTransactionRequest {
                gas_price: Some(wei),
                sender: Some(grpc_addr),
                chain_id: Some(chain_id),
                transaction_hash: vec![],
            };
            let request = tonic::Request::new(request_0);
            let response: Response<SendTransactionReply> = client.send_transaction(request).await.unwrap();

            println!(
                "SendTransactionReply status: {:?}", response.into_inner()
            );
        }
    }

}
