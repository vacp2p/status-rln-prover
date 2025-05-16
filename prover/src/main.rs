mod args;
// mod epoch_service;
mod error;
mod grpc_service;
mod registry;
mod registry_listener;

// std
use std::net::SocketAddr;
// third-party
use alloy::primitives::address;
// use chrono::{
//     DateTime,
//     Utc
// };
use clap::Parser;
use rln_proof::RlnIdentifier;
use tracing::level_filters::LevelFilter;
use tracing::{
    debug,
    error,
    // info
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
// internal
use crate::args::AppArgs;
// use crate::epoch_service::EpochService;
use crate::grpc_service::GrpcProverService;
use crate::registry_listener::RegistryListener;

const RLN_IDENTIFIER_NAME: &[u8] = b"test-rln-identifier";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    let app_args = AppArgs::parse();
    debug!("Arguments: {:?}", app_args);

    // Smart contract

    let uniswap_token_address = address!("1f9840a85d5aF5bf1D1762F925BDADdC4201F984");
    let event = "Transfer(address,address,uint256)";
    let registry_listener =
        RegistryListener::new(app_args.rpc_url.as_str(), uniswap_token_address, event);

    // Epoch
    // let mut epoch_service = EpochService::new(
    //     Duration::from_secs(10),
    //     Utc::now()
    // );

    // grpc

    let rln_identifier = RlnIdentifier::new(RLN_IDENTIFIER_NAME);
    let addr = SocketAddr::new(app_args.ip, app_args.port);
    debug!("Listening on: {}", addr);
    let prover_service = GrpcProverService::new(
        addr,
        rln_identifier,
        // epoch_service.current_epoch.clone()
    );

    let res = tokio::try_join!(
        // epoch_service.listen_for_new_epoch(),
        registry_listener.listen(),
        prover_service.serve(),
    );

    match res {
        // Ok((epoch, registry, prover)) => {
        Ok((registry, prover)) => {
            debug!("{:?}", registry);
            debug!("{:?}", prover);
        }
        Err(e) => {
            error!("{:?}", e);
        }
    }

    Ok(())
}
