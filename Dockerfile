# Stage 1: Build Prover
FROM rust:1.87-slim-bookworm AS builder

RUN apt update && apt install -y pkg-config libssl-dev protobuf-compiler

# Working directory
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY prover ./prover
COPY rln_proof ./rln_proof
COPY smart_contract ./smart_contract
RUN cargo build --release

# Stage 2: Run Prover
FROM ubuntu:25.04

RUN groupadd -r user && useradd -r -g user user

WORKDIR /app

# Copy the entrypoint script and make it executable
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy from the builder stage
COPY --from=builder /app/target/release/status_rln_prover ./status_rln_prover
COPY mock ./mock

RUN chown -R user:user /app
RUN chown user:user /usr/local/bin/docker-entrypoint.sh

USER user

# Exppose default port
EXPOSE 50051

# Run the prover - shell script will build arguments with parsed env var
ENTRYPOINT ["docker-entrypoint.sh"]

# Define default env variables. These will be used if not overridden during `docker run`.
ENV SERVICE_IP="0.0.0.0" \
    SERVICE_PORT="50051"