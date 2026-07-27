# syntax=docker/dockerfile:1

# ---- build stage ----
# Cargo.toml pins edition = "2024"; rust:1 tracks current stable which supports it.
FROM rust:1 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# ---- runtime stage ----
# debian:bookworm-slim (not distroless): hiqlite (sqlite) and reqwest/rustls need a
# glibc + basic CA-certs runtime; safer default than guessing at fully-static linking.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/plaste /usr/local/bin/plaste

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
