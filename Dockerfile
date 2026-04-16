# ---- Builder Stage ----
FROM rust:1.94-alpine AS builder

WORKDIR /app

# Install build dependencies for Alpine
RUN apk add --no-cache musl-dev pkgconfig

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
FROM alpine:latest AS runtime

WORKDIR /app

# Install CA certificates for secure upstream connections
RUN apk add --no-cache ca-certificates

# Copy the binary from the builder
COPY --from=builder /app/registry-proxy /app/registry-proxy

EXPOSE 4873
ENV PORT=4873

# Standard Alpine run
CMD ["/app/registry-proxy"]
