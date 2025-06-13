mod args;
// mod epoch_service;
mod epoch_service;
mod error;
mod grpc_service;
mod mock;
mod proof_generation;
mod proof_service;
mod registry_listener;
mod tier;
mod tiers_listener;
mod user_db_service;

// std
use std::net::SocketAddr;
use std::time::Duration;
// third-party
use alloy::primitives::U256;
use chrono::{DateTime, Utc};
use clap::Parser;
use rln_proof::RlnIdentifier;
use smart_contract::KarmaTiersSC::KarmaTiersSCInstance;
use smart_contract::TIER_LIMITS;
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
use crate::mock::read_mock_user;
use crate::proof_service::ProofService;
use crate::registry_listener::RegistryListener;
use crate::tiers_listener::TiersListener;
use crate::user_db_service::{RateLimit, UserDbService};

const RLN_IDENTIFIER_NAME: &[u8] = b"test-rln-identifier";
const PROVER_SPAM_LIMIT: RateLimit = RateLimit::new(10_000u64);
const PROOF_SERVICE_COUNT: u8 = 8;
const GENESIS: DateTime<Utc> = DateTime::from_timestamp(1431648000, 0).unwrap();
const PROVER_MINIMAL_AMOUNT_FOR_REGISTRATION: U256 =
    U256::from_le_slice(10u64.to_le_bytes().as_slice());

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

    // Application cli arguments checks
    if app_args.ws_rpc_url.is_some() {
        if app_args.ksc_address.is_none()
            || app_args.ksc_address.is_none()
            || app_args.tsc_address.is_none()
        {
            return Err("Please provide smart contract addresses".into());
        }
    } else if app_args.mock_sc.is_none() {
        return Err("Please provide rpc url (--ws-rpc-url) or mock (--mock-sc)".into());
    }

    // Epoch
    let epoch_service = EpochService::try_from((Duration::from_secs(60 * 2), GENESIS))
        .expect("Failed to create epoch service");

    let tier_limits = if app_args.ws_rpc_url.is_some() {
        KarmaTiersSCInstance::get_tiers(
            app_args.ws_rpc_url.clone().unwrap(),
            app_args.tsc_address.unwrap(),
        )
        .await?
    } else {
        // mock
        debug!("Mock - will use tier limits: {:#?}", TIER_LIMITS);
        TIER_LIMITS.clone()
    };

    // User db service
    let user_db_service = UserDbService::new(
        epoch_service.epoch_changes.clone(),
        epoch_service.current_epoch.clone(),
        PROVER_SPAM_LIMIT,
        tier_limits,
    );

    if app_args.mock_sc.is_some() {
        if let Some(user_filepath) = app_args.mock_user.as_ref() {
            let mock_users = read_mock_user(user_filepath).unwrap();
            debug!("Mock - will register {} users", mock_users.len());
            mock_users.into_iter().for_each(|mock_user| {
                debug!(
                    "Registering user address: {} - tx count: {}",
                    mock_user.address, mock_user.tx_count
                );
                let user_db = user_db_service.get_user_db();
                user_db.on_new_user(mock_user.address).unwrap();
                user_db
                    .on_new_tx(&mock_user.address, Some(mock_user.tx_count))
                    .unwrap();
            })
        }
    }

    // Smart contract
    // let karma_sc_address = address!("1f9840a85d5aF5bf1D1762F925BDADdC4201F984");
    let registry_listener = if app_args.mock_sc.is_some() {
        None
    } else {
        Some(RegistryListener::new(
            app_args.ws_rpc_url.clone().unwrap().as_str(),
            app_args.ksc_address.unwrap(),
            user_db_service.get_user_db(),
            PROVER_MINIMAL_AMOUNT_FOR_REGISTRATION,
        ))
    };

    let tiers_listener = if app_args.mock_sc.is_some() {
        None
    } else {
        Some(TiersListener::new(
            app_args.ws_rpc_url.clone().unwrap().as_str(),
            app_args.tsc_address.unwrap(),
            user_db_service.get_user_db(),
        ))
    };

    // proof service
    // FIXME: bound
    let (tx, rx) = tokio::sync::broadcast::channel(2);
    // TODO: bounded channel
    let (proof_sender, proof_receiver) = async_channel::unbounded();

    // grpc

    let rln_identifier = RlnIdentifier::new(RLN_IDENTIFIER_NAME);
    let addr = SocketAddr::new(app_args.ip, app_args.port);
    debug!("Listening on: {}", addr);
    // TODO: broadcast subscribe?
    let prover_grpc_service = {
        let mut service = GrpcProverService {
            proof_sender,
            broadcast_channel: (tx.clone(), rx),
            addr,
            rln_identifier,
            user_db: user_db_service.get_user_db(),
            karma_sc_info: None,
            rln_sc_info: None,
        };

        if app_args.ws_rpc_url.is_some() {
            let ws_rpc_url = app_args.ws_rpc_url.clone().unwrap();
            service.karma_sc_info = Some((ws_rpc_url.clone(), app_args.ksc_address.unwrap()));
            service.rln_sc_info = Some((ws_rpc_url, app_args.rlnsc_address.unwrap()));
        }
        service
    };

    let mut set = JoinSet::new();
    for _i in 0..PROOF_SERVICE_COUNT {
        let proof_recv = proof_receiver.clone();
        let broadcast_sender = tx.clone();
        let current_epoch = epoch_service.current_epoch.clone();
        let user_db = user_db_service.get_user_db();

        set.spawn(async {
            let proof_service = ProofService::new(
                proof_recv,
                broadcast_sender,
                current_epoch,
                user_db,
                PROVER_SPAM_LIMIT,
            );
            proof_service.serve().await
        });
    }

    if registry_listener.is_some() {
        set.spawn(async move { registry_listener.unwrap().listen().await });
    }
    if tiers_listener.is_some() {
        set.spawn(async move { tiers_listener.unwrap().listen().await });
    }
    set.spawn(async move { epoch_service.listen_for_new_epoch().await });
    set.spawn(async move { user_db_service.listen_for_epoch_changes().await });
    if app_args.ws_rpc_url.is_some() {
        set.spawn(async move { prover_grpc_service.serve().await });
    } else {
        debug!("Grpc service started with mocked smart contracts");
        set.spawn(async move { prover_grpc_service.serve_with_mock().await });
    }

    let _ = set.join_all().await;
    Ok(())
}
