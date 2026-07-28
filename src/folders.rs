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
        .route(
            "/folders/{id}",
            axum::routing::get(list_folder).delete(delete_folder).patch(update_folder),
        )
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

/// Walks the folder subtree (BFS) and returns `id` plus every descendant folder id, non-deleted
/// only. Shared by `delete_folder`'s cascade and `update_folder`'s cycle check (a move into any
/// id in this list, other than `id` itself for the self-check, would create a cycle).
async fn collect_with_descendants(
    state: &AppState,
    id: i64,
) -> Result<Vec<i64>, (StatusCode, &'static str)> {
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
    Ok(all_ids)
}

async fn delete_folder(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let folder = fetch_folder(&state, id).await?;
    check_access(&state, &ctx, id, &folder, Action::Write).await?;

    let deleted_at = chrono::Utc::now().to_rfc3339();

    let all_ids = collect_with_descendants(&state, id).await?;

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

// ---------- rename / move ----------

#[derive(Deserialize)]
struct UpdateFolderReq {
    name: Option<String>,
    #[serde(default, deserialize_with = "crate::files::deserialize_some")]
    parent_id: Option<Option<i64>>,
}

#[derive(Serialize)]
struct FolderUpdateResp {
    id: i64,
    name: String,
    parent_id: Option<i64>,
}

struct NameParentRow {
    name: String,
    parent_id: Option<i64>,
}
impl From<&mut hiqlite::Row<'_>> for NameParentRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { name: row.get("name"), parent_id: row.get("parent_id") }
    }
}

async fn update_folder(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
    Json(req): Json<UpdateFolderReq>,
) -> Result<Json<FolderUpdateResp>, (StatusCode, &'static str)> {
    let folder = fetch_folder(&state, id).await?;
    check_access(&state, &ctx, id, &folder, Action::Write).await?;

    let np: NameParentRow = state
        .db
        .query_map_optional("SELECT name, parent_id FROM folders WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "folder not found"))?;

    let parent_changing = req.parent_id.is_some();
    let target_parent_id = req.parent_id.unwrap_or(np.parent_id);

    if parent_changing {
        if let Some(target) = target_parent_id {
            if target == id {
                return Err((StatusCode::BAD_REQUEST, "cannot move a folder into itself"));
            }
            // Cycle check: moving `id` under any of its own descendants would orphan the tree.
            let descendants = collect_with_descendants(&state, id).await?;
            if descendants.contains(&target) {
                return Err((StatusCode::BAD_REQUEST, "cannot move a folder into its own descendant"));
            }
            let target_folder = fetch_folder(&state, target).await?;
            check_access(&state, &ctx, target, &target_folder, Action::Write).await?;
        }
    }

    let new_name = req.name.clone().unwrap_or_else(|| np.name.clone());

    if req.name.is_some() || parent_changing {
        // Same name+parent_id+owner matching as create_folder/files' collision check.
        let collision: Option<IdRow> = match target_parent_id {
            Some(pid) => {
                state
                    .db
                    .query_map_optional(
                        "SELECT id FROM folders WHERE name = $1 AND parent_id = $2 AND owner_token_id = $3 \
                         AND deleted_at IS NULL AND id != $4",
                        params!(&new_name, pid, folder.owner_token_id, id),
                    )
                    .await
            }
            None => {
                state
                    .db
                    .query_map_optional(
                        "SELECT id FROM folders WHERE name = $1 AND parent_id IS NULL AND owner_token_id = $2 \
                         AND deleted_at IS NULL AND id != $3",
                        params!(&new_name, folder.owner_token_id, id),
                    )
                    .await
            }
        }
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        if collision.is_some() {
            return Err((StatusCode::CONFLICT, "a folder with that name already exists under the target parent"));
        }
    }

    state
        .db
        .execute(
            "UPDATE folders SET name = $1, parent_id = $2 WHERE id = $3",
            params!(&new_name, target_parent_id, id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(
        &state.db,
        ctx.id,
        "folder.rename_or_move",
        Some("folder"),
        Some(id),
        Some(&new_name),
    )
    .await;

    Ok(Json(FolderUpdateResp { id, name: new_name, parent_id: target_parent_id }))
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

    async fn make_folder(state: &AppState, owner: i64, name: &str, parent_id: Option<i64>) -> i64 {
        let created_at = chrono::Utc::now().to_rfc3339();
        let row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO folders (parent_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(parent_id, name, owner, created_at),
            )
            .await
            .unwrap();
        row.id
    }

    async fn patch_folder(app: &Router, token: &str, id: i64, body: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/folders/{id}"))
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
    async fn rename_folder_persists() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let folder_id = make_folder(&state, owner, "old", None).await;
        let app = router().with_state(state);

        let (status, json) = patch_folder(&app, &token, folder_id, r#"{"name":"new"}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["name"], "new");
    }

    #[tokio::test]
    async fn moving_folder_into_own_descendant_returns_400() {
        let (state, _dir) = setup().await;
        let (owner, token) = make_token(&state.db).await;
        let parent_id = make_folder(&state, owner, "parent", None).await;
        let child_id = make_folder(&state, owner, "child", Some(parent_id)).await;
        let app = router().with_state(state);

        // Attempt to move "parent" under its own child "child" -> cycle, rejected.
        let (status, _json) = patch_folder(&app, &token, parent_id, &format!(r#"{{"parent_id":{child_id}}}"#)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

