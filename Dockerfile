# ---- Builder Stage ----
FROM rust:1.94-bookworm-slim AS builder

WORKDIR /app

# Install build dependencies (minimal pkg-config if needed, but no libssl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create a dummy source file to pre-compile dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies with cache mounts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release

# Copy the real source
COPY src ./src

# Build the application
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/registry-proxy /app/registry-proxy

# ---- Runtime Stage ----
FROM gcr.io/distroless/cc-debian12 AS runtime

WORKDIR /app

# Copy the binary from the builder
COPY --from=builder /app/registry-proxy /app/registry-proxy

EXPOSE 4873

ENV PORT=4873

CMD ["/app/registry-proxy"]
