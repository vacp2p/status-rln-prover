#!/bin/bash

# Array to hold the command-line arguments
CMD_ARGS=()

CMD_ARGS+=("--ip" "${SERVICE_IP}")
CMD_ARGS+=("--port" "${SERVICE_PORT}")

if [ -n "$WS_RPC_URL" ]; then
    CMD_ARGS+=("--ws-rpc-url" "${WS_RPC_URL}")
fi

if [ -n "$KARMA_SC_ADDRESS" ]; then
    CMD_ARGS+=("--ksc" "${KARMA_SC_ADDRESS}")
fi

if [ -n "$RLN_SC_ADDRESS" ]; then
    CMD_ARGS+=("--rlnsc" "${RLN_SC_ADDRESS}")
fi

if [ -n "$KARMA_TIERS_SC_ADDRESS" ]; then
    CMD_ARGS+=("--tsc" "${KARMA_TIERS_SC_ADDRESS}")
fi

if [ -n "$MOCK_SC" ]; then
    CMD_ARGS+=("--mock-sc" "true")
fi

if [ -n "$MOCK_USER" ]; then
    CMD_ARGS+=("--mock-user" "${MOCK_USER}")
fi

echo "Starting rln-prover-service with arguments: ${CMD_ARGS[*]}"
export RUST_LOG=debug
exec ./status_rln_prover "${CMD_ARGS[@]}"