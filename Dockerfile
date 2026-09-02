# syntax=docker/dockerfile:1

# ---- build stage ----
# Cargo.toml pins edition = "2024"; rust:1-bookworm tracks current stable while pinning
# the same Debian release as the runtime stage below. Plain `rust:1` floats onto whatever
# Debian release is current (e.g. trixie's glibc 2.38+), which is newer than
# debian:bookworm-slim's glibc — the resulting binary then fails to even start at runtime
# ("version `GLIBC_2.38' not found"), before any of our own code (or its logging) runs.
FROM rust:1-bookworm AS builder
WORKDIR /app

# Dummy build first: caches the dependency-compile layer (the slow part — hiqlite,
# tantivy, opendal, rustls) so it's skipped entirely unless Cargo.toml/Cargo.lock change,
# not on every source edit. Combined with BuildKit cache mounts below so the cargo
# registry + incremental target artifacts also survive across CI runs, not just within
# one image build. Cache mounts aren't part of the final layer, so the binary is copied
# out to a plain path before each cached RUN ends.
#
# `id=` + `sharing=locked` on both mounts: two workflows (docker.yml on manual dispatch,
# release.yml's docker-image job on tag push) both build this image with cache-from/to
# type=gha against the same repo, so their builds can overlap. Without an explicit id
# the cache scope is the mount target path — shared by both, and the default
# `sharing=shared` lets a second build read/write the same target/ dir mid-compile.
# That let one build's `cp target/release/plaste` grab a partially-written or stale
# (possibly still-dummy) binary from the other build's in-progress compile — a real
# build succeeding while silently shipping the wrong artifact. `sharing=locked` makes
# overlapping builds queue for the mount instead of interleaving.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN --mount=type=cache,id=plaste-cargo-registry,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=plaste-cargo-target,sharing=locked,target=/app/target \
    cargo build --release && rm -rf src

COPY src ./src
# Detruire les artefacts DU CRATE avant le vrai build. Les dependances restent
# dans le cache — c'est tout l'interet du pre-build — mais le binaire factice et
# son empreinte disparaissent.
#
# Sans ca, cargo ne recompilait pas : BuildKit normalise les mtime des fichiers
# copies, donc les sources reelles paraissent plus vieilles que les artefacts du
# pre-build et sont jugees inchangees. Le `cp` exportait alors le binaire
# `fn main() {}` : 450 Ko qui sortent avec le code 0 sans rien afficher, soit un
# CrashLoopBackOff dont chaque etat est « Completed ». Constate le 02/09/2026,
# mais deja livre par le build du 31/08 sans que personne ne le voie.
#
# Le `test` de taille est la garde qui manquait : un no-op ne doit plus jamais
# pouvoir passer pour un serveur. Le binaire reel depasse largement 5 Mo
# (tantivy, hiqlite, rustls).
RUN --mount=type=cache,id=plaste-cargo-registry,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=plaste-cargo-target,sharing=locked,target=/app/target \
    rm -f target/release/plaste \
    && rm -rf target/release/.fingerprint/plaste-* \
    && cargo build --release \
    && taille=$(stat -c%s target/release/plaste) \
    && if [ "$taille" -lt 5000000 ]; then \
         echo "ERREUR: binaire de ${taille} octets — le pre-build factice a ete livre" >&2; \
         exit 1; \
       fi \
    && cp target/release/plaste /app/plaste

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
