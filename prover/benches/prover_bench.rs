use criterion::Criterion;
use criterion::{BenchmarkId, Throughput};
use criterion::{criterion_group, criterion_main};

// std
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
// third-party
use alloy::primitives::{Address, U256};
use futures::FutureExt;
use parking_lot::RwLock;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tonic::Response;
// internal
use prover::{AppArgs, run_prover};

// grpc
pub mod prover_proto {
    // Include generated code (see build.rs)
    tonic::include_proto!("prover");
}
use prover_proto::{
    Address as GrpcAddress, RegisterUserReply, RegisterUserRequest, RegistrationStatus,
    RlnProofFilter, RlnProofReply, SendTransactionReply, SendTransactionRequest, U256 as GrpcU256,
    Wei as GrpcWei, rln_prover_client::RlnProverClient,
};

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
    }
}

async fn proof_collector(port: u16, proof_count: usize) -> Vec<RlnProofReply> {
    let result = Arc::new(RwLock::new(vec![]));

    let url = format!("http://127.0.0.1:{}", port);
    let mut client = RlnProverClient::connect(url).await.unwrap();

    let request_0 = RlnProofFilter { address: None };

    let request = tonic::Request::new(request_0);
    let stream_ = client.get_proofs(request).await.unwrap();
    let mut stream = stream_.into_inner();
    let result_2 = result.clone();
    let mut proof_received = 0;
    while let Some(response) = stream.message().await.unwrap() {
        result_2.write().push(response);
        proof_received += 1;
        if proof_received >= proof_count {
            break;
        }
    }

    std::mem::take(&mut *result.write())
}

fn proof_generation_bench(c: &mut Criterion) {
    let start = std::time::Instant::now();
    let rayon_num_threads = std::env::var("RAYON_NUM_THREADS").unwrap_or("".to_string());
    let proof_service_count_default = 4;
    let proof_service_count = std::env::var("PROOF_SERVICE_COUNT")
        .map(|c| u16::from_str(c.as_str()).unwrap_or(proof_service_count_default))
        .unwrap_or(proof_service_count_default);
    let proof_count_default = 5;
    let proof_count = std::env::var("PROOF_COUNT")
        .map(|c| u32::from_str(c.as_str()).unwrap_or(proof_count_default))
        .unwrap_or(proof_count_default);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let port = 50051;
    let temp_folder = tempfile::tempdir().unwrap();
    let temp_folder_tree = tempfile::tempdir().unwrap();
    // let proof_service_count = 4;
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
        metrics_port: 30051,
        broadcast_channel_size: 100,
        proof_service_count,
        transaction_channel_size: 100,
        proof_sender_channel_size: 100,
    };

    let addresses = vec![
        Address::from_str("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap(),
        Address::from_str("0xb20a608c624Ca5003905aA834De7156C68b2E1d0").unwrap(),
    ];
    // Tokio notify - wait for some time after spawning run_prover then notify it's ready to accept
    // connections
    let notify_start = Arc::new(Notify::new());

    // Spawn prover
    let notify_start_1 = notify_start.clone();
    rt.spawn(async move {
        tokio::spawn(run_prover(app_args));
        tokio::time::sleep(Duration::from_secs(10)).await;
        println!("Prover is ready, notifying it...");
        notify_start_1.clone().notify_one();
    });

    let notify_start_2 = notify_start.clone();
    let addresses_0 = addresses.clone();

    // Wait for proof_collector to be connected and waiting for some proofs
    rt.block_on(async move {
        notify_start_2.notified().await;
        println!("Prover is ready, registering users...");
        register_users(port, addresses_0).await;
    });

    println!("Starting benchmark...");
    // let size: usize = 1024;

    let mut group = c.benchmark_group("prover_bench");
    // group.sampling_mode(criterion::SamplingMode::Flat);

    // let proof_count = 5;
    let proof_count = proof_count as usize;

    group.throughput(Throughput::Elements(proof_count as u64));
    let benchmark_name = format!(
        "prover_proof_{}_proof_service_{}_rt_{}",
        proof_count, proof_service_count, rayon_num_threads
    );
    group.bench_with_input(
        BenchmarkId::new(benchmark_name, proof_count),
        &proof_count,
        |b, &_s| {
            b.to_async(&rt).iter(|| {
                async {
                    let mut set = JoinSet::new();
                    set.spawn(proof_collector(port, proof_count));
                    set.spawn(proof_sender(port, addresses.clone(), proof_count).map(|_r| vec![]));
                    // Wait for proof_sender + proof_collector to complete
                    let res = set.join_all().await;
                    // Check we receive enough proof
                    assert_eq!(res[1].len(), proof_count);
                }
            });
        },
    );

    group.finish();
    println!("Benchmark finished in {:?}", start.elapsed());
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(150))
    ;
    targets = proof_generation_bench
);
criterion_main!(benches);
