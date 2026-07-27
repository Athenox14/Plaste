use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{
    acl::{self, Action},
    auth::TokenCtx,
    db::IdRow,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/folders", axum::routing::post(create_folder).get(list_root))
        .route("/folders/{id}", axum::routing::get(list_folder).delete(delete_folder))
}

#[derive(Deserialize)]
struct CreateFolderReq {
    name: String,
    parent_id: Option<i64>,
}

#[derive(Serialize)]
struct FolderResp {
    id: i64,
    name: String,
    parent_id: Option<i64>,
}

/// Row shape for `SELECT owner_token_id, deleted_at FROM folders WHERE id = $1`.
struct FolderOwnerRow {
    owner_token_id: i64,
    deleted_at: Option<String>,
}

impl From<&mut hiqlite::Row<'_>> for FolderOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            owner_token_id: row.get("owner_token_id"),
            deleted_at: row.get("deleted_at"),
        }
    }
}

#[derive(Serialize)]
struct SubFolder {
    id: i64,
    name: String,
    created_at: String,
}

struct SubFolderRow {
    id: i64,
    name: String,
    created_at: String,
}

impl From<&mut hiqlite::Row<'_>> for SubFolderRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Serialize)]
struct FileEntry {
    id: i64,
    name: String,
    size: i64,
    created_at: String,
}

struct FileEntryRow {
    id: i64,
    name: String,
    size: i64,
    created_at: String,
}

impl From<&mut hiqlite::Row<'_>> for FileEntryRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            size: row.get("size"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Serialize)]
struct FolderContents {
    folders: Vec<SubFolder>,
    files: Vec<FileEntry>,
}

/// Fetches a folder's owner and soft-delete status, checking existence.
async fn fetch_folder(
    state: &AppState,
    id: i64,
) -> Result<FolderOwnerRow, (StatusCode, &'static str)> {
    let row: Option<FolderOwnerRow> = state
        .db
        .query_map_optional(
            "SELECT owner_token_id, deleted_at FROM folders WHERE id = $1",
            params!(id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    row.ok_or((StatusCode::NOT_FOUND, "folder not found"))
}

async fn check_access(
    state: &AppState,
    ctx: &TokenCtx,
    id: i64,
    row: &FolderOwnerRow,
    action: Action,
) -> Result<(), (StatusCode, &'static str)> {
    if row.deleted_at.is_some() {
        return Err((StatusCode::NOT_FOUND, "folder not found"));
    }
    if acl::check_access(&state.db, ctx, "folder", id, action).await {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "not owner"))
    }
}

async fn create_folder(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreateFolderReq>,
) -> Result<Json<FolderResp>, (StatusCode, &'static str)> {
    if let Some(parent_id) = req.parent_id {
        let parent = fetch_folder(&state, parent_id).await?;
        check_access(&state, &ctx, parent_id, &parent, Action::Write).await?;
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO folders (parent_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
            params!(req.parent_id, &req.name, ctx.id, created_at),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(&state.db, ctx.id, "folder.create", Some("folder"), Some(id_row.id), None).await;

    Ok(Json(FolderResp {
        id: id_row.id,
        name: req.name,
        parent_id: req.parent_id,
    }))
}

async fn fetch_contents(
    state: &AppState,
    parent_clause_id: Option<i64>,
    owner_scope: Option<i64>,
) -> Result<FolderContents, (StatusCode, &'static str)> {
    // ponytail: two near-identical query shapes (root vs child) collapsed via
    // optional owner_scope param instead of building dynamic SQL.
    let folders: Vec<SubFolderRow> = if let Some(owner) = owner_scope {
        state
            .db
            .query_map(
                "SELECT id, name, created_at FROM folders WHERE parent_id IS NULL AND owner_token_id = $1 AND deleted_at IS NULL",
                params!(owner),
            )
            .await
    } else {
        state
            .db
            .query_map(
                "SELECT id, name, created_at FROM folders WHERE parent_id = $1 AND deleted_at IS NULL",
                params!(parent_clause_id),
            )
            .await
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let files: Vec<FileEntryRow> = if let Some(owner) = owner_scope {
        state
            .db
            .query_map(
                "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS size, f.created_at AS created_at \
                 FROM files f LEFT JOIN file_versions v ON v.id = f.current_version_id \
                 WHERE f.folder_id IS NULL AND f.owner_token_id = $1 AND f.deleted_at IS NULL",
                params!(owner),
            )
            .await
    } else {
        state
            .db
            .query_map(
                "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS size, f.created_at AS created_at \
                 FROM files f LEFT JOIN file_versions v ON v.id = f.current_version_id \
                 WHERE f.folder_id = $1 AND f.deleted_at IS NULL",
                params!(parent_clause_id),
            )
            .await
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(FolderContents {
        folders: folders
            .into_iter()
            .map(|r| SubFolder {
                id: r.id,
                name: r.name,
                created_at: r.created_at,
            })
            .collect(),
        files: files
            .into_iter()
            .map(|r| FileEntry {
                id: r.id,
                name: r.name,
                size: r.size,
                created_at: r.created_at,
            })
            .collect(),
    })
}

async fn list_folder(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<Json<FolderContents>, (StatusCode, &'static str)> {
    let folder = fetch_folder(&state, id).await?;
    check_access(&state, &ctx, id, &folder, Action::Read).await?;
    let contents = fetch_contents(&state, Some(id), None).await?;
    Ok(Json(contents))
}

#[derive(Deserialize)]
struct ListRootQuery {
    #[allow(dead_code)]
    parent_id: Option<i64>,
}

async fn list_root(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Query(_query): Query<ListRootQuery>,
) -> Result<Json<FolderContents>, (StatusCode, &'static str)> {
    let contents = fetch_contents(&state, None, Some(ctx.id)).await?;
    Ok(Json(contents))
}

async fn delete_folder(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let folder = fetch_folder(&state, id).await?;
    check_access(&state, &ctx, id, &folder, Action::Write).await?;

    let deleted_at = chrono::Utc::now().to_rfc3339();

    // Walk the folder subtree to collect all descendant folder ids (BFS).
    let mut all_ids = vec![id];
    let mut frontier = vec![id];
    while !frontier.is_empty() {
        let mut next_frontier = Vec::new();
        for parent in frontier {
            let children: Vec<IdRow> = state
                .db
                .query_map(
                    "SELECT id FROM folders WHERE parent_id = $1 AND deleted_at IS NULL",
                    params!(parent),
                )
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
            for c in children {
                all_ids.push(c.id);
                next_frontier.push(c.id);
            }
        }
        frontier = next_frontier;
    }

    for folder_id in &all_ids {
        state
            .db
            .execute(
                "UPDATE folders SET deleted_at = $1 WHERE id = $2",
                params!(&deleted_at, *folder_id),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        state
            .db
            .execute(
                "UPDATE files SET deleted_at = $1 WHERE folder_id = $2",
                params!(&deleted_at, *folder_id),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    }

    crate::audit::log(&state.db, ctx.id, "folder.delete", Some("folder"), Some(id), None).await;

    Ok(StatusCode::NO_CONTENT)
}
