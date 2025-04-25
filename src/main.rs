mod args;
mod error;
mod grpc_service;
mod registry_listener;

// std
use std::net::SocketAddr;
// third-party
use alloy::primitives::address;
use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing::{
    debug,
    error,
    // info
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

// internal
use crate::args::AppArgs;
use crate::grpc_service::GrpcProverService;
use crate::registry_listener::RegistryListener;

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

    // grpc

    let addr = SocketAddr::new(app_args.ip, app_args.port);
    debug!("Listening on: {}", addr);
    let prover_service = GrpcProverService::new(addr);

    let res = tokio::try_join!(prover_service.serve(), registry_listener.listen());

    match res {
        Ok((first, second)) => {
            debug!("{:?}", first);
            debug!("{:?}", second);
        }
        Err(e) => {
            error!("{:?}", e);
        }
    }

    Ok(())
}
