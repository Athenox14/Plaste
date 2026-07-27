use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{auth::TokenCtx, db::IdRow, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/trash", axum::routing::get(list_trash))
        .route("/trash/{id}", axum::routing::delete(purge).post(restore))
}

type ApiErr = (StatusCode, &'static str);

#[derive(Deserialize)]
struct TypeQuery {
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Serialize)]
struct TrashEntry {
    id: i64,
    name: String,
    deleted_at: String,
}

struct TrashRow {
    id: i64,
    name: String,
    deleted_at: String,
}
impl From<&mut hiqlite::Row<'_>> for TrashRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            deleted_at: row.get("deleted_at"),
        }
    }
}

#[derive(Serialize)]
struct TrashList {
    folders: Vec<TrashEntry>,
    files: Vec<TrashEntry>,
}

struct ManifestRow {
    manifest: String,
}
impl From<&mut hiqlite::Row<'_>> for ManifestRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            manifest: row.get("manifest"),
        }
    }
}

async fn list_trash(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<TrashList>, ApiErr> {
    // ponytail: admin scoped to their own token id here too — no "view everyone's
    // trash" was asked for, add an admin-wide query if that's ever needed.
    let folders: Vec<TrashRow> = state
        .db
        .query_map(
            "SELECT id, name, deleted_at FROM folders WHERE deleted_at IS NOT NULL AND owner_token_id = $1",
            params!(ctx.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let files: Vec<TrashRow> = state
        .db
        .query_map(
            "SELECT id, name, deleted_at FROM files WHERE deleted_at IS NOT NULL AND owner_token_id = $1",
            params!(ctx.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(TrashList {
        folders: folders
            .into_iter()
            .map(|r| TrashEntry {
                id: r.id,
                name: r.name,
                deleted_at: r.deleted_at,
            })
            .collect(),
        files: files
            .into_iter()
            .map(|r| TrashEntry {
                id: r.id,
                name: r.name,
                deleted_at: r.deleted_at,
            })
            .collect(),
    }))
}

/// Checks the row exists, is soft-deleted, and (unless admin) owned by ctx.
async fn check_owned_deleted(
    state: &AppState,
    table: &str,
    id: i64,
    owner: Option<i64>,
) -> Result<bool, ApiErr> {
    let row: Option<IdRow> = if let Some(owner_id) = owner {
        let sql = format!(
            "SELECT id FROM {table} WHERE id = $1 AND owner_token_id = $2 AND deleted_at IS NOT NULL"
        );
        state.db.query_map_optional(sql, params!(id, owner_id)).await
    } else {
        let sql = format!("SELECT id FROM {table} WHERE id = $1 AND deleted_at IS NOT NULL");
        state.db.query_map_optional(sql, params!(id)).await
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(row.is_some())
}

async fn count_live_children(state: &AppState, folder_id: i64) -> Result<i64, ApiErr> {
    let mut row = state
        .db
        .query_raw_one(
            "SELECT \
                (SELECT COUNT(*) FROM folders WHERE parent_id = $1 AND deleted_at IS NULL) + \
                (SELECT COUNT(*) FROM files WHERE folder_id = $1 AND deleted_at IS NULL) AS n",
            params!(folder_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(row.get("n"))
}

fn table_for(kind: Option<&str>) -> Result<&'static str, ApiErr> {
    match kind {
        Some("file") => Ok("files"),
        Some("folder") => Ok("folders"),
        _ => Err((StatusCode::BAD_REQUEST, "type must be 'file' or 'folder'")),
    }
}

async fn restore(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Query(q): Query<TypeQuery>,
) -> Result<StatusCode, ApiErr> {
    let table = table_for(q.kind.as_deref())?;
    let owner = if ctx.is_admin { None } else { Some(ctx.id) };

    if !check_owned_deleted(&state, table, id, owner).await? {
        return Err((StatusCode::NOT_FOUND, "not found"));
    }

    let sql = format!("UPDATE {table} SET deleted_at = NULL WHERE id = $1");
    state
        .db
        .execute(sql, params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(&state.db, ctx.id, "trash.restore", Some(table), Some(id), None).await;

    Ok(StatusCode::NO_CONTENT)
}

async fn purge(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Query(q): Query<TypeQuery>,
) -> Result<StatusCode, ApiErr> {
    let table = table_for(q.kind.as_deref())?;
    let owner = if ctx.is_admin { None } else { Some(ctx.id) };

    if !check_owned_deleted(&state, table, id, owner).await? {
        return Err((StatusCode::NOT_FOUND, "not found"));
    }

    purge_resource(&state, table, id).await?;

    crate::audit::log(&state.db, ctx.id, "trash.purge", Some(table), Some(id), None).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Permanently purges a soft-deleted `folders`/`files` row (caller must have already
/// verified it's soft-deleted and owned/authorized). Shared by the manual `DELETE
/// /trash/{id}` handler above and `retention::purge_expired_trash`'s automatic sweep,
/// so the chunk-refcount release logic (see gc::release_manifest) lives in one place.
///
/// Returns `Ok(false)` without deleting anything if `table == "folders"` and it still
/// has non-deleted children (mirrors the manual handler's 409 case, but as a skip
/// rather than an error since the sweep has no HTTP response to give).
pub(crate) async fn purge_resource(state: &AppState, table: &str, id: i64) -> Result<bool, ApiErr> {
    if table == "folders" {
        if count_live_children(state, id).await? > 0 {
            return Ok(false);
        }
        state
            .db
            .execute("DELETE FROM folders WHERE id = $1", params!(id))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    } else {
        let versions: Vec<ManifestRow> = state
            .db
            .query_map(
                "SELECT manifest FROM file_versions WHERE file_id = $1",
                params!(id),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

        state
            .db
            .execute("DELETE FROM file_versions WHERE file_id = $1", params!(id))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        state
            .db
            .execute("DELETE FROM files WHERE id = $1", params!(id))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

        // Each file_versions row was one manifest-reference; release one ref per row,
        // per chunk. Sharing (across versions or files, e.g. via restore) is handled by
        // the refcount arithmetic itself, not by deduping hashes here.
        for v in versions {
            let manifest: Vec<String> = serde_json::from_str(&v.manifest).unwrap_or_default();
            crate::gc::release_manifest(&state.db, &state.storage, &manifest).await;
        }

        state.fts.remove_file(id).await;
    }

    Ok(true)
}
