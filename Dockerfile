# ---- Builder Stage ----
# Using official Rust Bookworm Slim image for high compatibility with Distroless Debian 12
FROM rust:1.94-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
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
# Distroless CC image includes only glibc and basic C++ libs for minimal attack surface
FROM gcr.io/distroless/cc-debian13 AS runtime

WORKDIR /app

# Run as nonroot user for enhanced security
# Distroless images come with a 'nonroot' user (UID 65532) out of the box
USER nonroot

# Copy the binary from the builder with correct ownership
COPY --from=builder --chown=nonroot:nonroot /app/registry-proxy /app/registry-proxy

EXPOSE 4873

ENV PORT=4873

# Execute binary directly (no shell in distroless)
CMD ["/app/registry-proxy"]
