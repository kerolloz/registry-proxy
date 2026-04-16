# ---- Planner Stage ----
FROM lukemathwalker/cargo-chef:latest-rust-1.85-bookworm AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Builder Stage ----
FROM lukemathwalker/cargo-chef:latest-rust-1.85-bookworm AS builder
WORKDIR /app

# Copy the recipe from the planner
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies
RUN cargo chef cook --release --recipe-path recipe.json

# Build the real source
COPY . .
RUN cargo build --release && \
    cp target/release/registry-proxy /app/registry-proxy

# ---- Runtime Stage ----
FROM gcr.io/distroless/cc-debian12 AS runtime

WORKDIR /app

# Copy the binary from the builder
COPY --from=builder /app/registry-proxy /app/registry-proxy

EXPOSE 4873

ENV PORT=4873

CMD ["/app/registry-proxy"]
