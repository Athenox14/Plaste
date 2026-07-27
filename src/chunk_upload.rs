//! Chunk-aware upload protocol: lets a client compute its own content-defined chunks,
//! ask the server which ones it's missing, and only transmit those — actual bandwidth
//! dedup, unlike `/files/upload` which always sends the whole file (storage-at-rest is
//! deduped there, but the transfer itself isn't). See `files.rs`'s existing
//! upload/upload-delta/tus paths, which stay as whole-file-transfer options.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{
    auth::TokenCtx,
    files::{self, ApiErr, StoreOutcome},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/chunks/check", post(check_missing))
        // axum's default body-limit middleware caps requests at 2MiB; a chunk can be up to
        // MAX (4MiB, see storage.rs's FastCDC constants) — raise the ceiling for this route
        // only, with headroom, rather than disabling it crate-wide.
        .route("/chunks/upload/{hash}", post(upload_chunk).layer(DefaultBodyLimit::max(8 * 1024 * 1024)))
        .route("/files/finalize", post(finalize))
}

/// Row for the `chunks` existence/size lookup below (`hash` is TEXT, don't map via `IdRow`).
struct ChunkRow {
    #[allow(dead_code)]
    hash: String,
    size: i64,
}
impl From<&mut hiqlite::Row<'_>> for ChunkRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { hash: row.get("hash"), size: row.get("size") }
    }
}

async fn chunk_row(state: &AppState, hash: &str) -> Option<ChunkRow> {
    state
        .db
        .query_map_optional::<ChunkRow, _>("SELECT hash, size FROM chunks WHERE hash = $1", params!(hash))
        .await
        .ok()
        .flatten()
}

// ---------- POST /chunks/check ----------

#[derive(Deserialize)]
struct CheckReq {
    hashes: Vec<String>,
}

#[derive(Serialize)]
struct CheckResp {
    missing: Vec<String>,
}

async fn check_missing(
    State(state): State<AppState>,
    _ctx: TokenCtx,
    Json(req): Json<CheckReq>,
) -> Result<Json<CheckResp>, ApiErr> {
    let mut missing = Vec::new();
    for hash in req.hashes {
        if chunk_row(&state, &hash).await.is_none() {
            missing.push(hash);
        }
    }
    Ok(Json(CheckResp { missing }))
}

// ---------- POST /chunks/upload/{hash} ----------

#[derive(Serialize)]
struct OkResp {
    ok: bool,
}

/// Uploads one chunk's plaintext bytes. Rejects (400) if `hash` doesn't match the received
/// bytes' actual BLAKE3 — the client's claimed hash is never trusted blindly. Ensures a
/// `chunks` row exists (refcount left untouched if it already does; inserted at refcount 0
/// if new) so `/files/finalize` can find it — the real "this manifest references it"
/// refcount bump happens once, in finalize, not here, so uploading a chunk that's never
/// finalized doesn't leak a phantom reference.
async fn upload_chunk(
    State(state): State<AppState>,
    _ctx: TokenCtx,
    Path(hash): Path<String>,
    bytes: Bytes,
) -> Result<Json<OkResp>, ApiErr> {
    let actual = blake3::hash(&bytes).to_hex().to_string();
    if actual != hash {
        return Err((StatusCode::BAD_REQUEST, "hash does not match uploaded bytes"));
    }

    if chunk_row(&state, &hash).await.is_none() {
        state
            .storage
            .write_single_chunk(&hash, &bytes)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage write failed"))?;
        state
            .db
            .execute(
                "INSERT INTO chunks (hash, size, refcount) VALUES ($1, $2, 0) ON CONFLICT(hash) DO NOTHING",
                params!(&hash, bytes.len() as i64),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    }

    Ok(Json(OkResp { ok: true }))
}

// ---------- POST /files/finalize ----------

#[derive(Deserialize)]
struct FinalizeReq {
    folder_id: Option<i64>,
    name: String,
    manifest: Vec<String>,
    #[allow(dead_code)]
    size: i64,
    expected_base_version: Option<i64>,
}

/// Assembles an already-fully-uploaded manifest into a new file version. Every hash in
/// `manifest` must already exist in the `chunks` table (uploaded via `/chunks/upload/{hash}`
/// first) — this endpoint does not accept new chunk bytes. Real size is re-summed from the
/// `chunks` table rather than trusting the client-provided `size` field.
async fn finalize(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<FinalizeReq>,
) -> Result<Json<files::UploadResp>, ApiErr> {
    let mut real_size: i64 = 0;
    for hash in &req.manifest {
        let row = chunk_row(&state, hash)
            .await
            .ok_or((StatusCode::BAD_REQUEST, "manifest references a chunk that was never uploaded"))?;
        real_size += row.size;
    }

    if ctx.used_bytes + real_size > ctx.quota_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "quota exceeded"));
    }

    // Find-or-create the files row (same lookup `upload` in files.rs does).
    let existing_file: Option<i64> = match req.folder_id {
        Some(fid) => state
            .db
            .query_raw_one(
                "SELECT id FROM files WHERE name = $1 AND folder_id = $2 AND owner_token_id = $3 AND deleted_at IS NULL",
                params!(&req.name, fid, ctx.id),
            )
            .await
            .ok()
            .map(|mut r| r.get("id")),
        None => state
            .db
            .query_raw_one(
                "SELECT id FROM files WHERE name = $1 AND folder_id IS NULL AND owner_token_id = $2 AND deleted_at IS NULL",
                params!(&req.name, ctx.id),
            )
            .await
            .ok()
            .map(|mut r| r.get("id")),
    };

    let file_id = if let Some(id) = existing_file {
        id
    } else {
        let created_at = chrono::Utc::now().to_rfc3339();
        let id_row: crate::db::IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO files (folder_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(req.folder_id, &req.name, ctx.id, created_at),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        id_row.id
    };

    let outcome = files::store_new_version_from_manifest(
        &state,
        file_id,
        req.manifest,
        real_size,
        req.expected_base_version,
        ctx.id,
    )
    .await?;

    state
        .db
        .execute(
            "UPDATE tokens SET used_bytes = used_bytes + $1 WHERE id = $2",
            params!(real_size, ctx.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    if !matches!(outcome, StoreOutcome::Conflict { .. }) {
        crate::audit::log(&state.db, ctx.id, "file.finalize", Some("file"), Some(file_id), None).await;
    }

    Ok(Json(files::UploadResp::from_outcome(file_id, outcome)))
}
