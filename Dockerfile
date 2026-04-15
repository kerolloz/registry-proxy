# ---- Build Stage ----
FROM rust:1.93-slim AS builder

WORKDIR /app

# Install build dependencies (required by openssl-sys / native-tls)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/registry_proxy*

# Build the real source
COPY src ./src
RUN cargo build --release

# ---- Runtime Stage ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/registry-proxy /app/registry-proxy

EXPOSE 4873

ENV PORT=4873

CMD ["/app/registry-proxy"]
