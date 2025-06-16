# Status L2 Rln Prover

## Docker

* docker build --progress=plain --no-cache -t prover .
* sudo docker run -p 50051:50051 prover --mock-sc true --mock-user mock/mock_user_1.json

## Run

RUST_LOG=debug cargo run -- -i 127.0.0.1 -r "wss://eth-mainnet.g.alchemy.com/v2/__MY_TOKEN__"

## Debug

* grpcurl -plaintext -d '{"sender": "Alice", "tx_id": "42"}' '[::1]:50051' prover.RlnProver/SendTransaction
* grpcurl -plaintext '[::1]:50051' prover.RlnProver/GetProofs