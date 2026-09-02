use axum::{
    body::Bytes,
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{
    acl::{self, Action},
    auth::TokenCtx,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/files/upload", post(upload))
        .route("/files/{id}/download", get(download))
        .route("/files/{id}/preview", get(preview))
        .route("/files/{id}/versions", get(list_versions))
        .route("/files/{id}/restore", post(restore))
        .route("/files/{id}", axum::routing::delete(delete_file).patch(update_file))
        .route("/files/{id}/signature", get(signature))
        .route("/files/{id}/upload-delta", post(upload_delta))
}

/// No module-owned tables currently; kept as a no-op hook (called from main.rs) in case
/// this module needs its own schema again.
pub async fn init_schema(_db: &hiqlite::Client) {}

pub(crate) type ApiErr = (StatusCode, &'static str);

/// Row for `files` lookups.
struct FileRow {
    id: i64,
    name: String,
    owner_token_id: i64,
    current_version_id: Option<i64>,
}
impl From<&mut hiqlite::Row<'_>> for FileRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            owner_token_id: row.get("owner_token_id"),
            current_version_id: row.get("current_version_id"),
        }
    }
}

/// Row for `file_versions` lookups.
struct VersionRow {
    id: i64,
    version_no: i64,
    size: i64,
    manifest: String,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for VersionRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            version_no: row.get("version_no"),
            size: row.get("size"),
            manifest: row.get("manifest"),
            created_at: row.get("created_at"),
        }
    }
}

use crate::db::IdRow;

/// Row for the chunk-dedup existence check in `store_new_version` (`chunks.hash` is TEXT).
struct HashRow {
    #[allow(dead_code)]
    hash: String,
}
impl From<&mut hiqlite::Row<'_>> for HashRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { hash: row.get("hash") }
    }
}

/// Fetches a file row, enforcing access (owner/admin/permissions-grant) and non-deleted, or 404.
async fn get_owned_file(state: &AppState, ctx: &TokenCtx, id: i64, action: Action) -> Result<FileRow, ApiErr> {
    let file: Option<FileRow> = state
        .db
        .query_map_optional(
            "SELECT id, name, owner_token_id, current_version_id FROM files WHERE id = $1 AND deleted_at IS NULL",
            params!(id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let file = file.ok_or((StatusCode::NOT_FOUND, "file not found"))?;
    if !acl::check_access(&state.db, ctx, "file", id, action).await {
        return Err((StatusCode::NOT_FOUND, "file not found"));
    }
    Ok(file)
}

/// Outcome of `store_new_version`: either a normal new version, or a detected conflict
/// resolved by spinning off a separate "conflicted copy" file (original left untouched).
pub(crate) enum StoreOutcome {
    Normal { version_id: i64, version_no: i64, size: i64 },
    Conflict { original_file_id: i64, conflicted_copy_file_id: i64, conflicted_copy_name: String, size: i64 },
}

/// Current `version_no` of `file_id`'s latest version (0 if it has none yet).
async fn current_version_no(state: &AppState, file_id: i64) -> Result<i64, ApiErr> {
    let mut row = state
        .db
        .query_raw_one(
            "SELECT MAX(version_no) AS max_ver FROM file_versions WHERE file_id = $1",
            params!(file_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let max_ver: Option<i64> = row.get("max_ver");
    Ok(max_ver.unwrap_or(0))
}

/// Splits `name` into (stem, ext-with-dot) for building conflicted-copy names, e.g.
/// "report.docx" -> ("report", ".docx"); "README" -> ("README", "").
fn split_name(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(0) | None => (name, ""),
        Some(idx) => (&name[..idx], &name[idx..]),
    }
}

/// Source of a new version's content: either raw bytes to be CDC-chunked and written fresh
/// (existing `upload`/`upload_delta`/tus callers), or an already-fully-uploaded manifest to
/// assemble directly with no chunking/writing step (chunk_upload.rs's finalize — chunks were
/// already transmitted individually via `POST /chunks/upload/{hash}`).
pub(crate) enum ContentSource<'a> {
    Raw(&'a [u8]),
    Manifest(Vec<String>, i64),
    /// Fichier sur disque, decoupe en flux : rien n'est charge entier en memoire.
    /// Voie des envois volumineux (tus), ou `Raw` ferait tomber le processus.
    Path(&'a std::path::Path),
}

/// Upserts one manifest-reference's worth of refcount for `hash`: increments if the `chunks`
/// row already exists, inserts a fresh row (refcount 1) otherwise. Shared by
/// `write_version_row_from_source` and chunk_upload.rs's finalize handler, so every path that
/// creates a new file_versions row reusing this hash bumps refcount exactly the same way.
pub(crate) async fn bump_or_insert_chunk_refcount(state: &AppState, hash: &str, size: i64) -> Result<(), ApiErr> {
    let existing = state
        .db
        .query_map_optional::<HashRow, _>("SELECT hash FROM chunks WHERE hash = $1", params!(hash))
        .await
        .ok()
        .flatten();
    if existing.is_some() {
        state
            .db
            .execute("UPDATE chunks SET refcount = refcount + 1 WHERE hash = $1", params!(hash))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    } else {
        state
            .db
            .execute(
                "INSERT INTO chunks (hash, size, refcount) VALUES ($1, $2, 1)",
                params!(hash, size),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    }
    Ok(())
}

/// Entry point shared by `upload`, `upload_delta`, and tus's `finish_upload`. If
/// `expected_base_version` is `Some` and doesn't match the file's current version_no,
/// this is a conflict: the new content is stored as version 1 of a brand-new
/// "conflicted copy" file instead of overwriting the original. `uploader_token_id` owns
/// that new file (same as whoever is doing this upload).
pub(crate) async fn store_new_version(
    state: &AppState,
    file_id: i64,
    data: &[u8],
    expected_base_version: Option<i64>,
    uploader_token_id: i64,
) -> Result<StoreOutcome, ApiErr> {
    store_new_version_impl(state, file_id, ContentSource::Raw(data), expected_base_version, uploader_token_id).await
}

/// Comme `store_new_version`, mais en lisant le contenu DEPUIS UN FICHIER, par
/// morceaux. Pour la finalisation d'un envoi resumable : le fichier partiel fait
/// deja plusieurs gigaoctets sur disque, le lire entierement en memoire
/// ferait tomber le processus.
pub(crate) async fn store_new_version_from_path(
    state: &AppState,
    file_id: i64,
    path: &std::path::Path,
    expected_base_version: Option<i64>,
    uploader_token_id: i64,
) -> Result<StoreOutcome, ApiErr> {
    store_new_version_impl(state, file_id, ContentSource::Path(path), expected_base_version, uploader_token_id).await
}

/// Same as `store_new_version` but for chunk_upload.rs's finalize: `manifest`'s chunks are
/// already fully present in the `chunks` table (verified by the caller), so this skips
/// chunking/writing and goes straight to the version-row/refcount/conflict-check tail.
pub(crate) async fn store_new_version_from_manifest(
    state: &AppState,
    file_id: i64,
    manifest: Vec<String>,
    size: i64,
    expected_base_version: Option<i64>,
    uploader_token_id: i64,
) -> Result<StoreOutcome, ApiErr> {
    store_new_version_impl(
        state,
        file_id,
        ContentSource::Manifest(manifest, size),
        expected_base_version,
        uploader_token_id,
    )
    .await
}

async fn store_new_version_impl(
    state: &AppState,
    file_id: i64,
    source: ContentSource<'_>,
    expected_base_version: Option<i64>,
    uploader_token_id: i64,
) -> Result<StoreOutcome, ApiErr> {
    if let Some(expected) = expected_base_version {
        let current = current_version_no(state, file_id).await?;
        if current != expected {
            let file: FileRow = state
                .db
                .query_map_optional(
                    "SELECT id, name, owner_token_id, current_version_id FROM files WHERE id = $1",
                    params!(file_id),
                )
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
                .ok_or((StatusCode::NOT_FOUND, "file not found"))?;
            let folder_id: Option<i64> = state
                .db
                .query_raw_one("SELECT folder_id FROM files WHERE id = $1", params!(file_id))
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
                .get("folder_id");

            let (stem, ext) = split_name(&file.name);
            let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S").to_string();
            let conflicted_copy_name = format!("{stem} (conflicted copy {timestamp}){ext}");
            let created_at = chrono::Utc::now().to_rfc3339();

            let new_file: IdRow = state
                .db
                .execute_returning_map_one(
                    "INSERT INTO files (folder_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                    params!(folder_id, &conflicted_copy_name, uploader_token_id, created_at),
                )
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

            let (_version_id, _version_no, size) = write_version_row_from_source(state, new_file.id, source).await?;

            crate::audit::log(
                &state.db,
                uploader_token_id,
                "file.conflict",
                Some("file"),
                Some(file_id),
                Some(&conflicted_copy_name),
            )
            .await;

            return Ok(StoreOutcome::Conflict {
                original_file_id: file_id,
                conflicted_copy_file_id: new_file.id,
                conflicted_copy_name,
                size,
            });
        }
    }

    let (version_id, version_no, size) = write_version_row_from_source(state, file_id, source).await?;
    Ok(StoreOutcome::Normal { version_id, version_no, size })
}

/// Chunk-writes `data` (or reuses an already-uploaded manifest), upserts chunk refcounts,
/// inserts a new `file_versions` row for `file_id`, and points `files.current_version_id` at
/// it. Returns (version_id, version_no, size).
async fn write_version_row_from_source(
    state: &AppState,
    file_id: i64,
    source: ContentSource<'_>,
) -> Result<(i64, i64, i64), ApiErr> {
    let (manifest, size) = match source {
        ContentSource::Raw(data) => state
            .storage
            .write(data)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage write failed"))?,
        ContentSource::Manifest(manifest, size) => (manifest, size),
        ContentSource::Path(path) => state
            .storage
            .write_from_path(path)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage write failed"))?,
    };

    for hash in &manifest {
        // `hash` is TEXT, not an i64 id — must not be mapped through `IdRow` (that panics
        // on the type mismatch inside hiqlite's row conversion whenever a matching chunk
        // is actually found, i.e. whenever dedup does its job).
        bump_or_insert_chunk_refcount(state, hash, size).await?;
    }

    let version_no = next_version_no(state, file_id).await?;
    let manifest_json =
        serde_json::to_string(&manifest).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "encode error"))?;
    let created_at = chrono::Utc::now().to_rfc3339();

    let version_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO file_versions (file_id, version_no, size, manifest, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            params!(file_id, version_no, size, manifest_json, created_at),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    state
        .db
        .execute(
            "UPDATE files SET current_version_id = $1 WHERE id = $2",
            params!(version_row.id, file_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok((version_row.id, version_no, size))
}

async fn next_version_no(state: &AppState, file_id: i64) -> Result<i64, ApiErr> {
    let mut row = state
        .db
        .query_raw_one(
            "SELECT MAX(version_no) AS max_ver FROM file_versions WHERE file_id = $1",
            params!(file_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let max_ver: Option<i64> = row.get("max_ver");
    Ok(max_ver.unwrap_or(0) + 1)
}

/// Reassembles a specific version's full content via `read_manifest`. Shared by the
/// signature and upload-delta (base reconstruction) handlers below.
async fn load_version_data(state: &AppState, file_id: i64, version_no: i64) -> Result<Vec<u8>, ApiErr> {
    let version: VersionRow = state
        .db
        .query_map_optional(
            "SELECT id, version_no, size, manifest, created_at FROM file_versions WHERE file_id = $1 AND version_no = $2",
            params!(file_id, version_no),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "version not found"))?;
    let manifest: Vec<String> = serde_json::from_str(&version.manifest)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "decode error"))?;
    state
        .storage
        .read_manifest(&manifest)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage read failed"))
}

// ---------- delta sync (signature / upload-delta) ----------

const RSYNC_SIGNATURE_OPTIONS: fast_rsync::SignatureOptions = fast_rsync::SignatureOptions {
    block_size: 4096,
    crypto_hash_size: 8,
};

#[derive(Deserialize)]
struct VersionQuery {
    version: i64,
}

/// Returns a serialized `fast_rsync::Signature` over the given version's content, so a
/// client can compute a delta against it locally.
async fn signature(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Query(q): Query<VersionQuery>,
) -> Result<impl IntoResponse, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Read).await?;
    let data = load_version_data(&state, file.id, q.version).await?;
    let sig = fast_rsync::Signature::calculate(&data, RSYNC_SIGNATURE_OPTIONS).into_serialized();
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream".to_string())],
        sig,
    ))
}

/// Body is raw `fast_rsync` delta bytes computed by the client against `base_version`'s
/// signature. Reassembles the base version, applies the delta, then stores the result
/// through the same `store_new_version` path as a normal upload.
async fn upload_delta(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Query(q): Query<BaseVersionQuery>,
    delta: Bytes,
) -> Result<Json<UploadResp>, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Write).await?;
    let base_data = load_version_data(&state, file.id, q.base_version).await?;

    let mut reconstructed = Vec::new();
    fast_rsync::apply(&base_data, &delta, &mut reconstructed)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid delta"))?;

    let new_size = reconstructed.len() as i64;
    if ctx.used_bytes + new_size > ctx.quota_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "quota exceeded"));
    }

    let outcome = store_new_version(&state, file.id, &reconstructed, Some(q.base_version), ctx.id).await?;
    let size = match &outcome {
        StoreOutcome::Normal { size, .. } | StoreOutcome::Conflict { size, .. } => *size,
    };

    state
        .db
        .execute(
            "UPDATE tokens SET used_bytes = used_bytes + $1 WHERE id = $2",
            params!(size, ctx.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    if !matches!(outcome, StoreOutcome::Conflict { .. }) {
        crate::audit::log(&state.db, ctx.id, "file.upload_delta", Some("file"), Some(file.id), None).await;
    }

    Ok(Json(UploadResp::from_outcome(file.id, outcome)))
}

#[derive(Deserialize)]
struct BaseVersionQuery {
    base_version: i64,
}

// ---------- upload ----------

#[derive(Default)]
struct UploadFields {
    folder_id: Option<i64>,
    name: Option<String>,
    data: Option<Bytes>,
    expected_base_version: Option<i64>,
}

/// Response shape for any upload-producing endpoint. `conflict` is always present so
/// callers can branch on one field; the normal-path fields are populated when
/// `conflict == false`, the conflict-path fields when `conflict == true`.
#[derive(Serialize)]
pub(crate) struct UploadResp {
    conflict: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_no: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_file_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicted_copy_file_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicted_copy_name: Option<String>,
    size: i64,
}

impl UploadResp {
    pub(crate) fn from_outcome(file_id: i64, outcome: StoreOutcome) -> Self {
        match outcome {
            StoreOutcome::Normal { version_id, version_no, size } => UploadResp {
                conflict: false,
                file_id: Some(file_id),
                version_id: Some(version_id),
                version_no: Some(version_no),
                original_file_id: None,
                conflicted_copy_file_id: None,
                conflicted_copy_name: None,
                size,
            },
            StoreOutcome::Conflict { original_file_id, conflicted_copy_file_id, conflicted_copy_name, size } => {
                UploadResp {
                    conflict: true,
                    file_id: None,
                    version_id: None,
                    version_no: None,
                    original_file_id: Some(original_file_id),
                    conflicted_copy_file_id: Some(conflicted_copy_file_id),
                    conflicted_copy_name: Some(conflicted_copy_name),
                    size,
                }
            }
        }
    }
}

async fn upload(
    State(state): State<AppState>,
    ctx: TokenCtx,
    mut multipart: Multipart,
) -> Result<Json<UploadResp>, ApiErr> {
    let mut fields = UploadFields::default();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid multipart"))?
    {
        match field.name().unwrap_or("") {
            "folder_id" => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| (StatusCode::BAD_REQUEST, "invalid folder_id"))?;
                if !text.is_empty() {
                    fields.folder_id = Some(
                        text.parse::<i64>()
                            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid folder_id"))?,
                    );
                }
            }
            "name" => {
                fields.name = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid name"))?,
                );
            }
            "file" => {
                fields.data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid file"))?,
                );
            }
            "expected_base_version" => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| (StatusCode::BAD_REQUEST, "invalid expected_base_version"))?;
                if !text.is_empty() {
                    fields.expected_base_version = Some(
                        text.parse::<i64>()
                            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid expected_base_version"))?,
                    );
                }
            }
            _ => {}
        }
    }

    let name = fields.name.ok_or((StatusCode::BAD_REQUEST, "missing name"))?;
    let data = fields.data.ok_or((StatusCode::BAD_REQUEST, "missing file"))?;
    let folder_id = fields.folder_id;

    // Quota check (using ctx snapshot from auth extractor; fine for MVP).
    let new_size = data.len() as i64;
    if ctx.used_bytes + new_size > ctx.quota_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "quota exceeded"));
    }

    // Find-or-create the files row.
    let existing_file: Option<FileRow> = match folder_id {
        Some(fid) => {
            state
                .db
                .query_map_optional(
                    "SELECT id, name, owner_token_id, current_version_id FROM files \
                     WHERE name = $1 AND folder_id = $2 AND owner_token_id = $3 AND deleted_at IS NULL",
                    params!(&name, fid, ctx.id),
                )
                .await
        }
        None => {
            state
                .db
                .query_map_optional(
                    "SELECT id, name, owner_token_id, current_version_id FROM files \
                     WHERE name = $1 AND folder_id IS NULL AND owner_token_id = $2 AND deleted_at IS NULL",
                    params!(&name, ctx.id),
                )
                .await
        }
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let created_at = chrono::Utc::now().to_rfc3339();

    let file_id = if let Some(f) = existing_file {
        f.id
    } else {
        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO files (folder_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(folder_id, &name, ctx.id, created_at.clone()),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        id_row.id
    };

    let outcome = store_new_version(&state, file_id, &data, fields.expected_base_version, ctx.id).await?;
    let size = match &outcome {
        StoreOutcome::Normal { size, .. } | StoreOutcome::Conflict { size, .. } => *size,
    };

    state
        .db
        .execute(
            "UPDATE tokens SET used_bytes = used_bytes + $1 WHERE id = $2",
            params!(size, ctx.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let (resp_file_id, index_name) = match &outcome {
        StoreOutcome::Normal { .. } => (file_id, name.clone()),
        StoreOutcome::Conflict { conflicted_copy_file_id, conflicted_copy_name, .. } => {
            (*conflicted_copy_file_id, conflicted_copy_name.clone())
        }
    };

    if matches!(outcome, StoreOutcome::Normal { .. }) {
        crate::audit::log(&state.db, ctx.id, "file.upload", Some("file"), Some(file_id), None).await;
    }

    let content = crate::fulltext::FullTextIndex::extractable_content(&index_name, &data);
    state
        .fts
        .index_file(resp_file_id, ctx.id, &index_name, content.as_deref())
        .await;

    Ok(Json(UploadResp::from_outcome(file_id, outcome)))
}

// ---------- download ----------

#[derive(Deserialize)]
struct DownloadQuery {
    version: Option<i64>,
}

async fn download(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Query(q): Query<DownloadQuery>,
) -> Result<impl IntoResponse, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Read).await?;

    let version: VersionRow = match q.version {
        Some(version_no) => state
            .db
            .query_map_optional(
                "SELECT id, version_no, size, manifest, created_at FROM file_versions WHERE file_id = $1 AND version_no = $2",
                params!(file.id, version_no),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
            .ok_or((StatusCode::NOT_FOUND, "version not found"))?,
        None => {
            let cur_id = file
                .current_version_id
                .ok_or((StatusCode::NOT_FOUND, "no current version"))?;
            state
                .db
                .query_map_optional(
                    "SELECT id, version_no, size, manifest, created_at FROM file_versions WHERE id = $1",
                    params!(cur_id),
                )
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
                .ok_or((StatusCode::NOT_FOUND, "version not found"))?
        }
    };

    let manifest: Vec<String> = serde_json::from_str(&version.manifest)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "decode error"))?;
    let data = state
        .storage
        .read_manifest(&manifest)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage read failed"))?;

    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (header::CONTENT_LENGTH, data.len().to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", file.name),
        ),
    ];

    Ok((headers, data))
}

// ---------- preview ----------

/// Extension (lowercased, no dot) -> mime type, for inline preview rendering.
fn mime_for_ext(name: &str) -> String {
    mime_guess::from_path(name).first_or_octet_stream().to_string()
}

/// Parses a single-range `Range: bytes=START-END` header value (the only form browsers
/// send for video/audio scrubbing). Returns `None` for anything else (multi-range,
/// malformed, `bytes=-N` suffix form), and the caller falls back to a full response.
/// Parses a single-range `Range` header value (`bytes=start-end`, `bytes=start-`,
/// or the suffix form `bytes=-len` meaning "last `len` bytes").
/// `pub` pour la cible de fuzzing (`fuzz/fuzz_targets/`), qui est une caisse
/// separee ne voyant que l'API publique. Reste un detail d'implementation.
pub fn parse_range(value: &str, total_len: usize) -> Option<(usize, usize)> {
    let spec = value.strip_prefix("bytes=")?;
    let (start_s, end_s) = spec.split_once('-')?;
    if start_s.is_empty() {
        // Suffix-range: last N bytes.
        let suffix_len: usize = end_s.parse().ok()?;
        if suffix_len == 0 || total_len == 0 {
            return None;
        }
        let start = total_len.saturating_sub(suffix_len);
        return Some((start, total_len - 1));
    }
    let start: usize = start_s.parse().ok()?;
    let end: usize = if end_s.is_empty() {
        total_len.checked_sub(1)?
    } else {
        end_s.parse().ok()?
    };
    if start > end || end >= total_len {
        return None;
    }
    Some((start, end))
}

async fn preview(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Read).await?;
    let cur_id = file
        .current_version_id
        .ok_or((StatusCode::NOT_FOUND, "no current version"))?;
    let version: VersionRow = state
        .db
        .query_map_optional(
            "SELECT id, version_no, size, manifest, created_at FROM file_versions WHERE id = $1",
            params!(cur_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "version not found"))?;

    let manifest: Vec<String> = serde_json::from_str(&version.manifest)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "decode error"))?;
    let data = state
        .storage
        .read_manifest(&manifest)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage read failed"))?;

    let mime = mime_for_ext(&file.name);
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_range(v, data.len()));

    match range {
        Some((start, end)) => {
            let slice = data[start..=end].to_vec();
            let resp_headers = [
                (header::CONTENT_TYPE, mime.to_string()),
                (header::CONTENT_LENGTH, slice.len().to_string()),
                (header::CONTENT_DISPOSITION, "inline".to_string()),
                (header::ACCEPT_RANGES, "bytes".to_string()),
                (
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", data.len()),
                ),
            ];
            Ok((StatusCode::PARTIAL_CONTENT, resp_headers, slice))
        }
        None => {
            let resp_headers = [
                (header::CONTENT_TYPE, mime.to_string()),
                (header::CONTENT_LENGTH, data.len().to_string()),
                (header::CONTENT_DISPOSITION, "inline".to_string()),
                (header::ACCEPT_RANGES, "bytes".to_string()),
                (header::CONTENT_RANGE, String::new()),
            ];
            Ok((StatusCode::OK, resp_headers, data))
        }
    }
}

// ---------- versions ----------

#[derive(Serialize)]
struct VersionResp {
    id: i64,
    version_no: i64,
    size: i64,
    created_at: String,
}

async fn list_versions(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<Json<Vec<VersionResp>>, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Read).await?;

    let rows: Vec<VersionRow> = state
        .db
        .query_map(
            "SELECT id, version_no, size, manifest, created_at FROM file_versions WHERE file_id = $1 ORDER BY version_no",
            params!(file.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(
        rows.into_iter()
            .map(|v| VersionResp {
                id: v.id,
                version_no: v.version_no,
                size: v.size,
                created_at: v.created_at,
            })
            .collect(),
    ))
}

// ---------- restore ----------

#[derive(Deserialize)]
struct RestoreQuery {
    version: i64,
}

async fn restore(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Query(q): Query<RestoreQuery>,
) -> Result<Json<VersionResp>, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Write).await?;

    let source: VersionRow = state
        .db
        .query_map_optional(
            "SELECT id, version_no, size, manifest, created_at FROM file_versions WHERE file_id = $1 AND version_no = $2",
            params!(file.id, q.version),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "version not found"))?;

    let new_version_no = next_version_no(&state, file.id).await?;
    let created_at = chrono::Utc::now().to_rfc3339();

    // A new file_versions row is a new reference to this manifest's chunks: bump refcount
    // to match, so purge later releases exactly what was reserved here (see gc::release_manifest).
    let reused_manifest: Vec<String> =
        serde_json::from_str(&source.manifest).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "decode error"))?;
    for hash in &reused_manifest {
        state
            .db
            .execute(
                "UPDATE chunks SET refcount = refcount + 1 WHERE hash = $1",
                params!(hash),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    }

    let new_version: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO file_versions (file_id, version_no, size, manifest, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            params!(file.id, new_version_no, source.size, &source.manifest, created_at.clone()),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    state
        .db
        .execute(
            "UPDATE files SET current_version_id = $1 WHERE id = $2",
            params!(new_version.id, file.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(
        &state.db,
        ctx.id,
        "file.restore",
        Some("file"),
        Some(file.id),
        Some(&q.version.to_string()),
    )
    .await;

    Ok(Json(VersionResp {
        id: new_version.id,
        version_no: new_version_no,
        size: source.size,
        created_at,
    }))
}

// ---------- delete ----------

#[cfg(test)]
mod preview_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn setup() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        init_schema(&db).await;
        let storage_dir = dir.path().join("chunks");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();
        let fts_dir = dir.path().join("fts_index");
        let fts = crate::fulltext::FullTextIndex::open_or_create(&fts_dir).unwrap();
        let state = AppState {
            db,
            storage: std::sync::Arc::new(crate::storage::ChunkStore::new(storage_dir)),
            chunks_dir: dir.path().join("chunks"),
            fts: std::sync::Arc::new(fts),
        };
        (state, dir)
    }

    async fn make_token(db: &hiqlite::Client) -> (i64, String) {
        let token = uuid::Uuid::new_v4().to_string();
        let row: IdRow = db
            .execute_returning_map_one(
                "INSERT INTO tokens (token, owner, created_at) VALUES ($1, 'u', $2) RETURNING id",
                params!(&token, chrono::Utc::now().to_rfc3339()),
            )
            .await
            .unwrap();
        (row.id, token)
    }

    /// Creates a file (with the given name, for extension/mime inference) and one version
    /// holding `data`, owned by `owner`. Returns the file id.
    async fn make_file_with_content(state: &AppState, owner: i64, name: &str, data: &[u8]) -> i64 {
        let created_at = chrono::Utc::now().to_rfc3339();
        let file: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO files (name, owner_token_id, created_at) VALUES ($1, $2, $3) RETURNING id",
                params!(name, owner, created_at),
            )
            .await
            .unwrap();
        store_new_version(state, file.id, data, None, owner).await.unwrap();
        file.id
    }

    #[tokio::test]
    async fn preview_without_range_returns_full_content_inline() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let data = b"%PDF-1.4 fake pdf content".to_vec();
        let file_id = make_file_with_content(&state, owner, "doc.pdf", &data).await;

        let app = router().with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/files/{file_id}/preview"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/pdf"
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "inline"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), data.as_slice());
    }

    #[tokio::test]
    async fn preview_with_range_returns_partial_content() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let data = b"0123456789abcdefghij".to_vec();
        let file_id = make_file_with_content(&state, owner, "clip.mp4", &data).await;

        let app = router().with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/files/{file_id}/preview"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("range", "bytes=2-5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 2-5/20"
        );
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "video/mp4");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"2345");
    }

    #[tokio::test]
    async fn preview_with_suffix_range_returns_last_bytes() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let data = b"0123456789abcdefghij".to_vec();
        let file_id = make_file_with_content(&state, owner, "clip.mp4", &data).await;

        let app = router().with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/files/{file_id}/preview"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("range", "bytes=-4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 16-19/20"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"ghij");
    }

}

#[cfg(test)]
mod conflict_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn setup() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        init_schema(&db).await;
        crate::audit::init_schema(&db).await;
        let storage_dir = dir.path().join("chunks");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();
        let fts_dir = dir.path().join("fts_index");
        let fts = crate::fulltext::FullTextIndex::open_or_create(&fts_dir).unwrap();
        let state = AppState {
            db,
            storage: std::sync::Arc::new(crate::storage::ChunkStore::new(storage_dir)),
            chunks_dir: dir.path().join("chunks"),
            fts: std::sync::Arc::new(fts),
        };
        (state, dir)
    }

    async fn make_token(db: &hiqlite::Client) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        db.execute(
            "INSERT INTO tokens (token, owner, quota_bytes, created_at) VALUES ($1, 'u', 999999999, $2)",
            params!(&token, chrono::Utc::now().to_rfc3339()),
        )
        .await
        .unwrap();
        token
    }

    /// Builds a `multipart/form-data` body with `name`, `file` and (optionally)
    /// `expected_base_version` fields.
    fn multipart_body(boundary: &str, name: &str, data: &[u8], expected_base_version: Option<i64>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{name}\r\n").as_bytes(),
        );
        if let Some(v) = expected_base_version {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"expected_base_version\"\r\n\r\n{v}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        body
    }

    async fn upload(
        app: &Router,
        token: &str,
        name: &str,
        data: &[u8],
        expected_base_version: Option<i64>,
    ) -> (StatusCode, serde_json::Value) {
        let boundary = "X-BOUNDARY-X";
        let body = multipart_body(boundary, name, data, expected_base_version);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/files/upload")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", format!("multipart/form-data; boundary={boundary}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn upload_without_expected_base_version_behaves_as_before() {
        let (state, _dir) = setup().await;
        let token = make_token(&state.db).await;
        let app = router().with_state(state);

        let (status, json) = upload(&app, &token, "a.txt", b"v1", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["conflict"], false);
        assert_eq!(json["version_no"], 1);

        // Second upload with no expected_base_version at all: normal version bump, same as
        // pre-conflict-detection behavior.
        let (status, json) = upload(&app, &token, "a.txt", b"v2", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["conflict"], false);
        assert_eq!(json["version_no"], 2);
    }

    #[tokio::test]
    async fn upload_with_matching_expected_base_version_succeeds_normally() {
        let (state, _dir) = setup().await;
        let token = make_token(&state.db).await;
        let app = router().with_state(state);

        let (_, json) = upload(&app, &token, "b.txt", b"v1", None).await;
        assert_eq!(json["version_no"], 1);

        let (status, json) = upload(&app, &token, "b.txt", b"v2", Some(1)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["conflict"], false);
        assert_eq!(json["version_no"], 2);
    }

    #[tokio::test]
    async fn upload_with_stale_expected_base_version_creates_conflicted_copy() {
        let (state, _dir) = setup().await;
        let token = make_token(&state.db).await;
        let app = router().with_state(state.clone());

        // v1
        let (_, json) = upload(&app, &token, "c.txt", b"content-v1", None).await;
        assert_eq!(json["version_no"], 1);

        // "Client A" bumps to v2, still believing base was v1.
        let (_, json) = upload(&app, &token, "c.txt", b"content-v2-clientA", Some(1)).await;
        assert_eq!(json["conflict"], false);
        assert_eq!(json["version_no"], 2);
        let original_file_id = json["file_id"].as_i64().unwrap();

        // "Client B" also thought base was v1 -- conflict.
        let (status, json) = upload(&app, &token, "c.txt", b"content-v2-clientB", Some(1)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["conflict"], true);
        assert_eq!(json["original_file_id"], original_file_id);
        let conflicted_id = json["conflicted_copy_file_id"].as_i64().unwrap();
        assert_ne!(conflicted_id, original_file_id);
        let conflicted_name = json["conflicted_copy_name"].as_str().unwrap();
        assert!(conflicted_name.starts_with("c (conflicted copy "));
        assert!(conflicted_name.ends_with(").txt"));

        // Original file is untouched: still v2 content.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/files/{original_file_id}/download"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"content-v2-clientA");

        // Conflicted copy holds client B's content as its own version 1.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/files/{conflicted_id}/download"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"content-v2-clientB");

        // Audit trail recorded the conflict.
        let mut row = state
            .db
            .query_raw_one(
                "SELECT COUNT(*) AS c FROM audit_log WHERE action = 'file.conflict' AND resource_id = $1",
                params!(original_file_id),
            )
            .await
            .unwrap();
        let count: i64 = row.get("c");
        assert_eq!(count, 1);
    }
}

async fn delete_file(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Write).await?;
    let deleted_at = chrono::Utc::now().to_rfc3339();
    state
        .db
        .execute(
            "UPDATE files SET deleted_at = $1 WHERE id = $2",
            params!(deleted_at, file.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    crate::audit::log(&state.db, ctx.id, "file.delete", Some("file"), Some(file.id), None).await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- rename / move ----------

/// Serde helper for the `folder_id` field of `PATCH /files/{id}` (and `PATCH /folders/{id}`'s
/// `parent_id`): distinguishes a JSON field that's entirely omitted (`None`, "leave unchanged")
/// from one explicitly present as `null` (`Some(None)`, "move to root") or a concrete id
/// (`Some(Some(id))`). Plain `Option<T>` can't tell "omitted" from "null"; pairing this with
/// `#[serde(default, deserialize_with = "deserialize_some")]` gets that distinction from
/// ordinary JSON, no client-side tricks required.
pub(crate) fn deserialize_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct UpdateFileReq {
    name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    folder_id: Option<Option<i64>>,
}

#[derive(Serialize)]
struct FileUpdateResp {
    id: i64,
    name: String,
    folder_id: Option<i64>,
}

struct DeletedAtRow {
    deleted_at: Option<String>,
}
impl From<&mut hiqlite::Row<'_>> for DeletedAtRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { deleted_at: row.get("deleted_at") }
    }
}

async fn update_file(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Json(req): Json<UpdateFileReq>,
) -> Result<Json<FileUpdateResp>, ApiErr> {
    let file = get_owned_file(&state, &ctx, id, Action::Write).await?;

    let current_folder_id: Option<i64> = state
        .db
        .query_raw_one("SELECT folder_id FROM files WHERE id = $1", params!(file.id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .get("folder_id");

    let folder_changing = req.folder_id.is_some();
    let target_folder_id = req.folder_id.unwrap_or(current_folder_id);

    if folder_changing {
        if let Some(target) = target_folder_id {
            let target_row: Option<DeletedAtRow> = state
                .db
                .query_map_optional("SELECT deleted_at FROM folders WHERE id = $1", params!(target))
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
            match target_row {
                None => return Err((StatusCode::NOT_FOUND, "target folder not found")),
                Some(r) if r.deleted_at.is_some() => {
                    return Err((StatusCode::NOT_FOUND, "target folder not found"))
                }
                _ => {}
            }
            if !acl::check_access(&state.db, &ctx, "folder", target, Action::Write).await {
                return Err((StatusCode::NOT_FOUND, "target folder not found"));
            }
        }
    }

    let new_name = req.name.clone().unwrap_or_else(|| file.name.clone());

    if req.name.is_some() || folder_changing {
        // Same name+folder_id+owner matching as upload's find-or-create, minus the current file.
        let collision: Option<IdRow> = match target_folder_id {
            Some(fid) => {
                state
                    .db
                    .query_map_optional(
                        "SELECT id FROM files WHERE name = $1 AND folder_id = $2 AND owner_token_id = $3 \
                         AND deleted_at IS NULL AND id != $4",
                        params!(&new_name, fid, file.owner_token_id, file.id),
                    )
                    .await
            }
            None => {
                state
                    .db
                    .query_map_optional(
                        "SELECT id FROM files WHERE name = $1 AND folder_id IS NULL AND owner_token_id = $2 \
                         AND deleted_at IS NULL AND id != $3",
                        params!(&new_name, file.owner_token_id, file.id),
                    )
                    .await
            }
        }
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        if collision.is_some() {
            return Err((StatusCode::CONFLICT, "a file with that name already exists in the target folder"));
        }
    }

    state
        .db
        .execute(
            "UPDATE files SET name = $1, folder_id = $2 WHERE id = $3",
            params!(&new_name, target_folder_id, file.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(
        &state.db,
        ctx.id,
        "file.rename_or_move",
        Some("file"),
        Some(file.id),
        Some(&new_name),
    )
    .await;

    Ok(Json(FileUpdateResp { id: file.id, name: new_name, folder_id: target_folder_id }))
}

#[cfg(test)]
mod rename_move_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn setup() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        init_schema(&db).await;
        crate::audit::init_schema(&db).await;
        let storage_dir = dir.path().join("chunks");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();
        let fts_dir = dir.path().join("fts_index");
        let fts = crate::fulltext::FullTextIndex::open_or_create(&fts_dir).unwrap();
        let state = AppState {
            db,
            storage: std::sync::Arc::new(crate::storage::ChunkStore::new(storage_dir)),
            chunks_dir: dir.path().join("chunks"),
            fts: std::sync::Arc::new(fts),
        };
        (state, dir)
    }

    async fn make_token(db: &hiqlite::Client) -> (i64, String) {
        let token = uuid::Uuid::new_v4().to_string();
        let row: IdRow = db
            .execute_returning_map_one(
                "INSERT INTO tokens (token, owner, quota_bytes, created_at) VALUES ($1, 'u', 999999999, $2) RETURNING id",
                params!(&token, chrono::Utc::now().to_rfc3339()),
            )
            .await
            .unwrap();
        (row.id, token)
    }

    async fn make_file(state: &AppState, owner: i64, name: &str, folder_id: Option<i64>) -> i64 {
        let created_at = chrono::Utc::now().to_rfc3339();
        let file: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO files (folder_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(folder_id, name, owner, created_at),
            )
            .await
            .unwrap();
        file.id
    }

    async fn make_folder(state: &AppState, owner: i64, name: &str) -> i64 {
        let created_at = chrono::Utc::now().to_rfc3339();
        let row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO folders (parent_id, name, owner_token_id, created_at) VALUES (NULL, $1, $2, $3) RETURNING id",
                params!(name, owner, created_at),
            )
            .await
            .unwrap();
        row.id
    }

    async fn patch_file(app: &Router, token: &str, id: i64, body: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/files/{id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn rename_file_name_only_persists() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let file_id = make_file(&state, owner, "old.txt", None).await;
        let app = router().with_state(state);

        let (status, json) = patch_file(&app, &token, file_id, r#"{"name":"new.txt"}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["name"], "new.txt");
        assert_eq!(json["folder_id"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn move_file_to_different_folder_only() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let folder_id = make_folder(&state, owner, "target").await;
        let file_id = make_file(&state, owner, "a.txt", None).await;
        let app = router().with_state(state);

        let (status, json) = patch_file(&app, &token, file_id, &format!(r#"{{"folder_id":{folder_id}}}"#)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["name"], "a.txt");
        assert_eq!(json["folder_id"], folder_id);
    }

    #[tokio::test]
    async fn rename_file_colliding_with_existing_name_in_target_returns_409() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let folder_id = make_folder(&state, owner, "target").await;
        let _existing = make_file(&state, owner, "taken.txt", Some(folder_id)).await;
        let file_id = make_file(&state, owner, "mine.txt", None).await;
        let app = router().with_state(state);

        let (status, _json) = patch_file(
            &app,
            &token,
            file_id,
            &format!(r#"{{"name":"taken.txt","folder_id":{folder_id}}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
