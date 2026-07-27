# Plaste

Self-hosted drive/sync server, written in Rust — chunked upload/download, cross-file dedup, encryption at rest, versioning, search, sharing, and a desktop sync client. Nextcloud/Dropbox-style, no third-party cloud dependency.

API-only management: there is no web admin UI or file-browser web app. Everything (users/tokens, folders/files, sharing, tags, comments, groups, storage backends...) is managed via REST or GraphQL. The only GUI is the desktop sync client.

## What's here

| Path | What it is |
|---|---|
| `src/` | Backend server (axum + hiqlite). REST, GraphQL, and an MCP server, all on one binary. |
| `client/` | Desktop sync client "Plaste Sync" (Tauri, Windows/macOS/Linux). |
| `.github/workflows/` | CI: Docker image build, multi-platform release build, auto-generated `DOC.md`. |
| `DOC.md` | Auto-generated module/endpoint map, regenerated on every push to `main`. |

## Features

- **Storage**: content-defined chunking (fastcdc) + BLAKE3 dedup, AES-256-GCM encryption at rest with key rotation, disk or S3 backend (opendal), automatic hot/cold tiering.
- **Sync**: chunked upload/download, tus resumable upload, fast_rsync delta-sync (only the diff travels the wire), conflict resolution (concurrent edits become a "conflicted copy," nothing is silently overwritten).
- **Files**: folders, versioning + restore, trash with configurable retention/auto-purge, tantivy full-text search, inline preview with Range-request streaming (PDF/image/video/etc.).
- **Sharing & collab**: public share links (password/expiry), per-user and per-group permissions (Casbin ACL), comments/mentions, tags, favorites.
- **Admin**: token-based auth (no classic login — admin issues time-limited tokens, 30-day default, renewable), per-user quotas, audit log, token-bucket rate limiting.
- **Integrations**: REST API, GraphQL API, a discoverable MCP server.
- **Desktop client**: filesystem watcher, selective sync, per-OS virtual/online-only files (Windows: Cloud Filter API; Linux: FUSE skeleton; **macOS: not available**, needs a native Swift extension out of scope here — the app tells you instead of failing silently).

## Running the backend

```sh
cargo run --release
# or: docker run -p 8080:8080 -v plaste-data:/data ghcr.io/athenox14/plaste:latest
```

First run prints a bootstrap admin token — that's your only way in, there's no signup form. Use it to mint scoped, expiring tokens for actual users via `POST /admin/tokens`.

Key env vars: `PLASTE_DATA_DIR` (default `./data`), `PLASTE_PORT` (default `8080`), `PLASTE_TLS_CERT`/`PLASTE_TLS_KEY` (enables HTTPS if both set), `PLASTE_STORAGE_BACKEND` (`fs` or `s3`, + `PLASTE_S3_*` vars), `PLASTE_MASTER_KEY` (base64 32-byte encryption key; auto-generated if unset).

## Running the desktop client

```sh
cd client/src-tauri && cargo tauri dev
```

Everything else — creating users/tokens, browsing/uploading files, sharing, tags, comments, groups, storage backends — goes through the API directly (`curl`, GraphQL client, or the MCP server) rather than a web UI.

## Releases

Prebuilt binaries (backend for Linux/Windows/macOS, desktop installers for all three) are published on the [Releases page](https://github.com/Athenox14/Plaste/releases). Trigger a new one via the "Release" GitHub Action (`workflow_dispatch`, pass a version like `v0.2.0`).

## Known gaps

- macOS virtual/online-only files — needs a native `NSFileProviderReplicatedExtension` (Swift/Xcode), out of scope for a pure-Rust project.
- Real-time collaborative document editing (OnlyOffice/Collabora) — deliberately not built; not a requirement for this project.
- No production hardening pass yet: single static encryption key rotation is manual (`POST /admin/rotate-key`), no clustering (hiqlite runs single-node), no metrics/monitoring beyond `tracing` logs.
