# syntax=docker/dockerfile:1

# ---- build stage ----
# Cargo.toml pins edition = "2024"; rust:1 tracks current stable which supports it.
FROM rust:1 AS builder
WORKDIR /app

# Dummy build first: caches the dependency-compile layer (the slow part — hiqlite,
# tantivy, opendal, rustls) so it's skipped entirely unless Cargo.toml/Cargo.lock change,
# not on every source edit. Combined with BuildKit cache mounts below so the cargo
# registry + incremental target artifacts also survive across CI runs, not just within
# one image build. Cache mounts aren't part of the final layer, so the binary is copied
# out to a plain path before each cached RUN ends.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && rm -rf src

COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && cp target/release/plaste /app/plaste

# ---- runtime stage ----
# debian:bookworm-slim (not distroless): hiqlite (sqlite) and reqwest/rustls need a
# glibc + basic CA-certs runtime; safer default than guessing at fully-static linking.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/plaste /usr/local/bin/plaste

EXPOSE 8080

# Environment variables (all optional, defaults shown where applicable):
#   PLASTE_DATA_DIR        - local data/db/chunk storage root (default ./data)
#   PLASTE_PORT             - HTTP listen port (default 8080)
#   PLASTE_TLS_CERT/_KEY    - paths to enable TLS; if both unset, server runs plain HTTP
#   PLASTE_STORAGE_BACKEND  - "fs" (default) or "s3"
#   PLASTE_S3_BUCKET/_REGION/_ACCESS_KEY/_SECRET_KEY/_ENDPOINT - required when backend=s3
#   PLASTE_ADMIN_TOKEN      - bootstrap admin auth token

ENV PLASTE_DATA_DIR=/data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/plaste"]
