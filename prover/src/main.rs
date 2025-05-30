mod args;
// mod epoch_service;
mod epoch_service;
mod error;
mod grpc_service;
mod proof_service;
mod registry;
mod registry_listener;
mod tier;
mod user_db_service;

// std
use std::net::SocketAddr;
use std::time::Duration;
// third-party
use chrono::{DateTime, Utc};
use clap::Parser;
use rln_proof::RlnIdentifier;
use tokio::task::JoinSet;
use tracing::level_filters::LevelFilter;
use tracing::{
    debug,
    // error,
    // info
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
// internal
use crate::args::AppArgs;
use crate::epoch_service::EpochService;
use crate::grpc_service::GrpcProverService;
use crate::proof_service::ProofService;
use crate::user_db_service::UserDbService;

const RLN_IDENTIFIER_NAME: &[u8] = b"test-rln-identifier";
const PROOF_SERVICE_COUNT: u8 = 8;
const GENESIS: DateTime<Utc> = DateTime::from_timestamp(1431648000, 0).unwrap();

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

    // let uniswap_token_address = address!("1f9840a85d5aF5bf1D1762F925BDADdC4201F984");
    // let event = "Transfer(address,address,uint256)";
    // let registry_listener =
    //     RegistryListener::new(app_args.rpc_url.as_str(), uniswap_token_address, event);

    // Epoch
    let epoch_service = EpochService::try_from((Duration::from_secs(60 * 2), GENESIS))
        .expect("Failed to create epoch service");

    // User db service
    let user_db_service = UserDbService::new(
        epoch_service.epoch_changes.clone(),
        epoch_service.current_epoch.clone(),
    );

    // proof service
    // FIXME: bound
    let (tx, rx) = tokio::sync::broadcast::channel(2);
    // TODO: bounded channel
    let (proof_sender, proof_receiver) = async_channel::unbounded();

    // grpc

    let rln_identifier = RlnIdentifier::new(RLN_IDENTIFIER_NAME);
    let addr = SocketAddr::new(app_args.ip, app_args.port);
    debug!("Listening on: {}", addr);
    let prover_grpc_service = GrpcProverService {
        proof_sender,
        broadcast_channel: (tx.clone(), rx),
        addr,
        rln_identifier,
        user_db: user_db_service.get_user_db(),
    };

    let mut set = JoinSet::new();
    for _i in 0..PROOF_SERVICE_COUNT {
        let proof_recv = proof_receiver.clone();
        let broadcast_sender = tx.clone();
        let current_epoch = epoch_service.current_epoch.clone();

        set.spawn(async {
            let proof_service = ProofService::new(proof_recv, broadcast_sender, current_epoch);
            proof_service.serve().await
        });
    }
    // set.spawn(async move { registry_listener.listen().await });
    set.spawn(async move { epoch_service.listen_for_new_epoch().await });
    set.spawn(async move { user_db_service.listen_for_epoch_changes().await });
    set.spawn(async move { prover_grpc_service.serve().await });

    let _ = set.join_all().await;
    Ok(())
}
