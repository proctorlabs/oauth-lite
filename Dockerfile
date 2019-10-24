FROM rust:latest as builder

# These two steps for caching purposes, keep rebuilds fast
ADD ["Cargo.toml", "Cargo.lock", "./"]
RUN mkdir -p src && touch src/main.rs && cargo update && (cargo build --release | true)

# Build the binary
ADD src/ src/
RUN cargo build --release

# This is our target image
FROM debian:buster-slim

RUN apt-get update && \
    apt-get install -y libssl1.1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder target/release/oauth-lite /usr/local/bin/oauth-lite
COPY www/ www/
ENTRYPOINT ["oauth-lite"]
