mod args;
// mod epoch_service;
mod epoch_service;
mod error;
mod grpc_service;
mod mock;
mod proof_generation;
mod proof_service;
mod registry_listener;
mod rocksdb_operands;
mod tier;
mod tiers_listener;
mod user_db;
mod user_db_error;
mod user_db_serialization;
mod user_db_service;
mod user_db_types;

// std
use std::net::SocketAddr;
use std::time::Duration;
// third-party
use alloy::primitives::U256;
use chrono::{DateTime, Utc};
use tokio::task::JoinSet;
use tracing::{
    debug,
    // error,
    // info
};
// internal
use rln_proof::RlnIdentifier;
use smart_contract::KarmaTiersSC::KarmaTiersSCInstance;
use smart_contract::TIER_LIMITS;
pub use crate::args::{AppArgs, AppArgsConfig};
use crate::epoch_service::EpochService;
use crate::grpc_service::GrpcProverService;
use crate::mock::read_mock_user;
use crate::proof_service::ProofService;
use crate::registry_listener::RegistryListener;
use crate::tier::TierLimits;
use crate::tiers_listener::TiersListener;
use crate::user_db_service::UserDbService;
use crate::user_db_types::RateLimit;

const RLN_IDENTIFIER_NAME: &[u8] = b"test-rln-identifier";
const PROVER_SPAM_LIMIT: RateLimit = RateLimit::new(10_000u64);
const GENESIS: DateTime<Utc> = DateTime::from_timestamp(1431648000, 0).unwrap();
const PROVER_MINIMAL_AMOUNT_FOR_REGISTRATION: U256 =
    U256::from_le_slice(10u64.to_le_bytes().as_slice());

pub async fn run_prover(app_args: AppArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {

    // Epoch
    let epoch_service = EpochService::try_from((Duration::from_secs(60 * 2), GENESIS))
        .expect("Failed to create epoch service");

    let mut tier_limits = if app_args.ws_rpc_url.is_some() {
        TierLimits::from(
            KarmaTiersSCInstance::get_tiers(
                app_args.ws_rpc_url.clone().unwrap(),
                app_args.tsc_address.unwrap(),
            )
                .await?,
        )
    } else {
        // mock
        let tl = TierLimits::from(TIER_LIMITS.clone());
        debug!("Mock - will use tier limits: {:#?}", tl);
        tl
    };

    tier_limits.filter_inactive();
    tier_limits.validate()?;

    // User db service
    let user_db_service = UserDbService::new(
        app_args.db_path.clone(),
        app_args.merkle_tree_path.clone(),
        epoch_service.epoch_changes.clone(),
        epoch_service.current_epoch.clone(),
        PROVER_SPAM_LIMIT,
        tier_limits,
    )?;

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
                user_db.on_new_user(&mock_user.address).unwrap();
                user_db
                    .on_new_tx(&mock_user.address, Some(mock_user.tx_count))
                    .unwrap();
            })
        }
    }

    // Smart contract
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
    let (tx, rx) = tokio::sync::broadcast::channel(app_args.broadcast_channel_size);
    let (proof_sender, proof_receiver) = async_channel::bounded(app_args.transaction_channel_size);

    // grpc

    let rln_identifier = RlnIdentifier::new(RLN_IDENTIFIER_NAME);
    let addr = SocketAddr::new(app_args.ip, app_args.port);
    debug!("Listening on: {}", addr);
    let prover_grpc_service = {
        let mut service = GrpcProverService {
            proof_sender,
            broadcast_channel: (tx.clone(), rx),
            addr,
            rln_identifier,
            user_db: user_db_service.get_user_db(),
            karma_sc_info: None,
            rln_sc_info: None,
            proof_sender_channel_size: app_args.proof_sender_channel_size,
        };

        if app_args.ws_rpc_url.is_some() {
            let ws_rpc_url = app_args.ws_rpc_url.clone().unwrap();
            service.karma_sc_info = Some((ws_rpc_url.clone(), app_args.ksc_address.unwrap()));
            service.rln_sc_info = Some((ws_rpc_url, app_args.rlnsc_address.unwrap()));
        }
        service
    };

    let mut set = JoinSet::new();
    for _i in 0..app_args.proof_service_count {
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

    // TODO: handle error
    let _ = set.join_all().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // std
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    // third-party
    use tokio::task;
    use tonic::Response;
    use alloy::{
        primitives::{Address, U256},
    };
    use tracing::info;
    use tracing_test::traced_test;
    use futures::FutureExt;
    use parking_lot::RwLock;
    // internal
    use crate::grpc_service::prover_proto::{
        Address as GrpcAddress,
        U256 as GrpcU256,
        Wei as GrpcWei,
        GetUserTierInfoReply, GetUserTierInfoRequest,
        RegisterUserReply, RegisterUserRequest, RegistrationStatus,
        SendTransactionRequest, SendTransactionReply,
        RlnProofFilter, RlnProofReply
    };
    use crate::grpc_service::prover_proto::rln_prover_client::RlnProverClient;

    async fn proof_sender(port: u16, addresses: Vec<Address>, proof_count: usize) {

        let chain_id = GrpcU256 {
            // FIXME: LE or BE?
            value: U256::from(1).to_le_bytes::<32>().to_vec(),
        };

        let url = format!("http://127.0.0.1:{}", port);
        let mut client = RlnProverClient::connect(url).await.unwrap();

        let addr = GrpcAddress {
            value: addresses[0].to_vec(),
        };
        let wei = GrpcWei {
            // FIXME: LE or BE?
            value: U256::from(1000).to_le_bytes::<32>().to_vec(),
        };
        let tx_hash = U256::from(42).to_le_bytes::<32>().to_vec();

        let request_0 = SendTransactionRequest {
            gas_price: Some(wei),
            sender: Some(addr),
            chain_id: Some(chain_id),
            transaction_hash: tx_hash,
        };

        let request = tonic::Request::new(request_0);
        let response: Response<SendTransactionReply> = client.send_transaction(request).await.unwrap();
        assert_eq!(response.into_inner().result, true);
    }

    async fn proof_collector(port: u16) -> Vec<RlnProofReply> {

        let result= Arc::new(RwLock::new(vec![]));

        let url = format!("http://127.0.0.1:{}", port);
        let mut client = RlnProverClient::connect(url).await.unwrap();

        let request_0 = RlnProofFilter {
            address: None,
        };

        let request = tonic::Request::new(request_0);
        let stream_ = client.get_proofs(request).await.unwrap();

        let mut stream = stream_.into_inner();

        let result_2 = result.clone();
        let receiver = async move {
            while let Some(response) = stream.message().await.unwrap() {
                result_2.write().push(response);
            }
        };

        let _res = tokio::time::timeout(Duration::from_secs(10), receiver).await;
        std::mem::take(&mut *result.write())
    }

    async fn register_users(port: u16, addresses: Vec<Address>) {

        let url = format!("http://127.0.0.1:{}", port);
        let mut client = RlnProverClient::connect(url).await.unwrap();

        for address in addresses {

            let addr = GrpcAddress {
                value: address.to_vec(),
            };

            let request_0 = RegisterUserRequest {
                user: Some(addr),
            };
            let request = tonic::Request::new(request_0);
            let response: Response<RegisterUserReply> = client.register_user(request).await.unwrap();

            assert_eq!(
                RegistrationStatus::try_from(response.into_inner().status).unwrap(),
                RegistrationStatus::Success);
        }
    }

    async fn query_user_info(port: u16, addresses: Vec<Address>) -> Vec<GetUserTierInfoReply> {

        let url = format!("http://127.0.0.1:{}", port);
        let mut client = RlnProverClient::connect(url).await.unwrap();

        let mut result = vec![];
        for address in addresses {
            let addr = GrpcAddress {
                value: address.to_vec(),
            };
            let request_0 = GetUserTierInfoRequest {
                user: Some(addr),
            };
            let request = tonic::Request::new(request_0);
            let resp: Response<GetUserTierInfoReply> = client.get_user_tier_info(request).await.unwrap();

            result.push(resp.into_inner());
        }

        result
    }

    #[tokio::test]
    #[traced_test]
    async fn test_grpc_register_users() {

        let addresses = vec![
            Address::from_str("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap(),
            Address::from_str("0xb20a608c624Ca5003905aA834De7156C68b2E1d0").unwrap(),
        ];

        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();

        let port = 50051;
        let app_args = AppArgs {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
            ws_rpc_url: None,
            db_path: temp_folder.path().to_path_buf(),
            merkle_tree_path: temp_folder_tree.path().to_path_buf(),
            ksc_address: None,
            rlnsc_address: None,
            tsc_address: None,
            mock_sc: Some(true),
            mock_user: None,
            config_path: Default::default(),
            no_config: Some(true),
            broadcast_channel_size: 100,
            proof_service_count: 8,
            transaction_channel_size: 100,
            proof_sender_channel_size: 100,
        };

        info!("Starting prover...");
        let prover_handle = task::spawn(run_prover(app_args));
        // Wait for the prover to be ready
        // Note: if unit test is failing - maybe add an optional notification when service is ready
        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("Registering some users...");
        register_users(port, addresses.clone()).await;
        info!("Query info for these new users...");
        let res = query_user_info(port, addresses.clone()).await;
        assert_eq!(res.len(), addresses.len());
        info!("Aborting prover...");
        prover_handle.abort();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    #[traced_test]
    async fn test_grpc_gen_proof() {

        let addresses = vec![
            Address::from_str("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap(),
            Address::from_str("0xb20a608c624Ca5003905aA834De7156C68b2E1d0").unwrap(),
        ];

        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();

        let port = 50052;
        let app_args = AppArgs {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
            ws_rpc_url: None,
            db_path: temp_folder.path().to_path_buf(),
            merkle_tree_path: temp_folder_tree.path().to_path_buf(),
            ksc_address: None,
            rlnsc_address: None,
            tsc_address: None,
            mock_sc: Some(true),
            mock_user: None,
            config_path: Default::default(),
            no_config: Some(true),
            broadcast_channel_size: 100,
            proof_service_count: 8,
            transaction_channel_size: 100,
            proof_sender_channel_size: 100,
        };

        info!("Starting prover...");
        let prover_handle = task::spawn(run_prover(app_args));
        // Wait for the prover to be ready
        // Note: if unit test is failing - maybe add an optional notification when service is ready
        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("Registering some users...");
        register_users(port, addresses.clone()).await;

        info!("Sending tx and collecting proofs...");
        let proof_count = 1;
        let mut set = JoinSet::new();
        set.spawn(
            proof_sender(port, addresses.clone(), proof_count)
                .map(|_| vec![]) // JoinSet require having the same return type
        );
        set.spawn(proof_collector(port));
        let res = set.join_all().await;

        assert_eq!(res[1].len(), proof_count);

        info!("Aborting prover...");
        prover_handle.abort();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
