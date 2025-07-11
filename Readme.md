# Status L2 Rln Prover

## Docker

* docker build --progress=plain --no-cache -t prover .
* sudo docker run -p 50051:50051 prover --mock-sc true --mock-user mock/mock_user_1.json

## Run prover

RUST_LOG=debug cargo run -p prover_cli -- -i 127.0.0.1 -r "wss://eth-mainnet.g.alchemy.com/v2/__MY_TOKEN__"

## Run prover + Mock

RUST_LOG=debug cargo run -p prover_cli -- -i 127.0.0.1 --metrics-ip 127.0.0.1 --mock-sc true --mock-user mock/mock_user_1.json 

## Run prover client (for tests)

RUST_LOG=debug cargo run -p prover_client

## Debug

* grpcurl -plaintext -d '{"sender": "Alice", "tx_id": "42"}' '[::1]:50051' prover.RlnProver/SendTransaction
* grpcurl -plaintext '[::1]:50051' prover.RlnProver/GetProofs