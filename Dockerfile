# ---- Planner Stage ----
FROM lukemathwalker/cargo-chef:latest-rust-alpine AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Builder Stage ----
FROM lukemathwalker/cargo-chef:latest-rust-alpine AS builder
WORKDIR /app

RUN apk add --no-cache musl-dev pkgconfig ca-certificates

# Copy the recipe from the planner
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies
RUN cargo chef cook --release --recipe-path recipe.json

# Build the real source
COPY . .
RUN cargo build --release && \
    cp target/release/registry-proxy /app/registry-proxy

# ---- Runtime Stage ----
FROM scratch AS runtime

WORKDIR /app

# Copy the CA certificates from the builder stage for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/registry-proxy /app/registry-proxy

EXPOSE 4873

ENV PORT=4873

CMD ["/app/registry-proxy"]
