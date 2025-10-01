use alloy::primitives::{Address, U256};
use futures::FutureExt;
use parking_lot::RwLock;
use prover::{AppArgs, MockUser, run_prover};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::task;
use tokio::task::JoinSet;
use tonic::Response;
use tracing::{debug, info};
use tracing_test::traced_test;

pub mod prover_proto {
    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
}
use crate::prover_proto::{
    Address as GrpcAddress, GetUserTierInfoReply, GetUserTierInfoRequest, RlnProofFilter,
    RlnProofReply, SendTransactionReply, SendTransactionRequest, U256 as GrpcU256, Wei as GrpcWei,
    rln_prover_client::RlnProverClient,
};

/*
async fn register_users(port: u16, addresses: Vec<Address>) {
    let url = format!("http://127.0.0.1:{}", port);
    let mut client = RlnProverClient::connect(url).await.unwrap();

    for address in addresses {
        let addr = GrpcAddress {
            value: address.to_vec(),
        };

        let request_0 = RegisterUserRequest { user: Some(addr) };
        let request = tonic::Request::new(request_0);
        let response: Response<RegisterUserReply> = client.register_user(request).await.unwrap();

        assert_eq!(
            RegistrationStatus::try_from(response.into_inner().status).unwrap(),
            RegistrationStatus::Success
        );
    }
}
*/

async fn query_user_info(port: u16, addresses: Vec<Address>) -> Vec<GetUserTierInfoReply> {
    let url = format!("http://127.0.0.1:{port}");
    let mut client = RlnProverClient::connect(url).await.unwrap();

    let mut result = vec![];
    for address in addresses {
        let addr = GrpcAddress {
            value: address.to_vec(),
        };
        let request_0 = GetUserTierInfoRequest { user: Some(addr) };
        let request = tonic::Request::new(request_0);
        let resp: Response<GetUserTierInfoReply> =
            client.get_user_tier_info(request).await.unwrap();

        result.push(resp.into_inner());
    }

    result
}

/*
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
        metrics_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        metrics_port: 30031,
        broadcast_channel_size: 100,
        proof_service_count: 16,
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
*/

async fn proof_sender(port: u16, addresses: Vec<Address>, proof_count: usize) {
    let start = std::time::Instant::now();

    let chain_id = GrpcU256 {
        // FIXME: LE or BE?
        value: U256::from(1).to_le_bytes::<32>().to_vec(),
    };

    let url = format!("http://127.0.0.1:{port}");
    let mut client = RlnProverClient::connect(url).await.unwrap();

    let addr = GrpcAddress {
        value: addresses[0].to_vec(),
    };
    let wei = GrpcWei {
        // FIXME: LE or BE?
        value: U256::from(1000).to_le_bytes::<32>().to_vec(),
    };

    let mut count = 0;
    for i in 0..proof_count {
        let tx_hash = U256::from(42 + i).to_le_bytes::<32>().to_vec();

        let request_0 = SendTransactionRequest {
            gas_price: Some(wei.clone()),
            sender: Some(addr.clone()),
            chain_id: Some(chain_id.clone()),
            transaction_hash: tx_hash,
        };

        let request = tonic::Request::new(request_0);
        let response: Response<SendTransactionReply> =
            client.send_transaction(request).await.unwrap();
        assert!(response.into_inner().result);
        count += 1;
    }

    println!(
        "[proof_sender] sent {} tx - elapsed: {} secs",
        count,
        start.elapsed().as_secs_f64()
    );
}

async fn proof_collector(port: u16, proof_count: usize) -> Vec<RlnProofReply> {
    let start = std::time::Instant::now();
    let result = Arc::new(RwLock::new(vec![]));

    let url = format!("http://127.0.0.1:{port}");
    let mut client = RlnProverClient::connect(url).await.unwrap();

    let request_0 = RlnProofFilter { address: None };

    let request = tonic::Request::new(request_0);
    let stream_ = client.get_proofs(request).await.unwrap();

    let mut stream = stream_.into_inner();

    let result_2 = result.clone();
    let mut count = 0;
    let mut start_per_message = std::time::Instant::now();
    let receiver = async move {
        while let Some(response) = stream.message().await.unwrap() {
            result_2.write().push(response);
            count += 1;
            if count >= proof_count {
                break;
            }
            println!(
                "count {count} - elapsed: {} secs",
                start_per_message.elapsed().as_secs_f64()
            );
            start_per_message = std::time::Instant::now();
        }
    };

    let _res = tokio::time::timeout(Duration::from_secs(500), receiver).await;
    println!("_res: {_res:?}");
    let res = std::mem::take(&mut *result.write());
    println!(
        "[proof_collector] elapsed: {} secs",
        start.elapsed().as_secs_f64()
    );
    res
}

#[tokio::test]
#[traced_test]
async fn test_grpc_gen_proof() {
    let mock_users = vec![
        MockUser {
            address: Address::from_str("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap(),
            tx_count: 0,
        },
        MockUser {
            address: Address::from_str("0xb20a608c624Ca5003905aA834De7156C68b2E1d0").unwrap(),
            tx_count: 0,
        },
    ];
    let addresses: Vec<Address> = mock_users.iter().map(|u| u.address).collect();

    // Write mock users to tempfile
    let mock_users_as_str = serde_json::to_string(&mock_users).unwrap();
    let mut temp_file = NamedTempFile::new().unwrap();
    let temp_file_path = temp_file.path().to_path_buf();
    temp_file.write_all(mock_users_as_str.as_bytes()).unwrap();
    temp_file.flush().unwrap();
    debug!(
        "Mock user temp file path: {}",
        temp_file_path.to_str().unwrap()
    );
    //

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
        mock_user: Some(temp_file_path),
        config_path: Default::default(),
        no_config: true,
        metrics_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        metrics_port: 30031,
        broadcast_channel_size: 500,
        proof_service_count: 8,
        transaction_channel_size: 500,
        proof_sender_channel_size: 500,
        registration_min_amount: AppArgs::default_minimal_amount_for_registration(),
        rln_identifier: AppArgs::default_rln_identifier_name(),
        spam_limit: AppArgs::default_spam_limit(),
    };

    info!("Starting prover with args: {:?}", app_args);
    let prover_handle = task::spawn(run_prover(app_args));
    // Wait for the prover to be ready
    // Note: if unit test is failing - maybe add an optional notification when service is ready
    tokio::time::sleep(Duration::from_secs(5)).await;
    // info!("Registering some users...");
    // register_users(port, addresses.clone()).await;
    info!("Query info for these new users...");
    let res = query_user_info(port, addresses.clone()).await;
    assert_eq!(res.len(), addresses.len());

    info!("Sending tx and collecting proofs...");
    let proof_count = 10;
    let mut set = JoinSet::new();
    set.spawn(
        proof_sender(port, addresses.clone(), proof_count).map(|_| vec![]), // JoinSet require having the same return type
    );
    set.spawn(proof_collector(port, proof_count));
    let res = set.join_all().await;

    println!("res lengths: {} {}", res[0].len(), res[1].len());
    assert_eq!(res[0].len() + res[1].len(), proof_count);

    info!("Aborting prover...");
    prover_handle.abort();
    tokio::time::sleep(Duration::from_secs(1)).await;
}
