use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{auth::TokenCtx, db::IdRow, AppState};

/// Own schema for tags/favorites, run separately from db.rs's SCHEMA array
/// (see main.rs merge note) to avoid touching code other agents are editing.
pub async fn init_schema(db: &hiqlite::Client) {
    const SCHEMA: &[&str] = &[
        r#"CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_token_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(owner_token_id, name)
        )"#,
        r#"CREATE TABLE IF NOT EXISTS resource_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resource_type TEXT NOT NULL,
            resource_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(resource_type, resource_id, tag_id)
        )"#,
        r#"CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_token_id INTEGER NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(owner_token_id, resource_type, resource_id)
        )"#,
    ];
    for stmt in SCHEMA {
        db.execute(*stmt, params!()).await.expect("tags schema init");
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/tags", axum::routing::post(create_tag).get(list_tags))
        .route("/tags/{id}", axum::routing::delete(delete_tag))
        .route(
            "/resource-tags",
            axum::routing::post(attach_tag).get(list_resource_tags),
        )
        .route("/resource-tags/{id}", axum::routing::delete(detach_tag))
        .route(
            "/favorites",
            axum::routing::post(add_favorite).get(list_favorites),
        )
        .route("/favorites/{id}", axum::routing::delete(remove_favorite))
}

fn db_err<E>(_: E) -> (StatusCode, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, "db error")
}

// ---------- rows ----------

struct TagRow {
    id: i64,
    name: String,
}
impl From<&mut hiqlite::Row<'_>> for TagRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
        }
    }
}

struct TagOwnerRow {
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for TagOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            owner_token_id: row.get("owner_token_id"),
        }
    }
}

struct ResourceTagOwnerRow {
    tag_owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for ResourceTagOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            tag_owner_token_id: row.get("tag_owner_token_id"),
        }
    }
}

struct FavoriteOwnerRow {
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for FavoriteOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            owner_token_id: row.get("owner_token_id"),
        }
    }
}

// ---------- payloads ----------

#[derive(Deserialize)]
struct CreateTagReq {
    name: String,
}

#[derive(Serialize)]
struct TagResp {
    id: i64,
    name: String,
}

#[derive(Deserialize)]
struct ResourceTagReq {
    resource_type: String,
    resource_id: i64,
    tag_id: i64,
}

#[derive(Serialize)]
struct ResourceTagResp {
    id: i64,
    resource_type: String,
    resource_id: i64,
    tag_id: i64,
}

#[derive(Deserialize)]
struct ResourceTagQuery {
    resource_type: String,
    resource_id: i64,
}

#[derive(Serialize)]
struct ResourceTagEntry {
    id: i64,
    tag_id: i64,
    name: String,
}

struct ResourceTagEntryRow {
    id: i64,
    tag_id: i64,
    name: String,
}
impl From<&mut hiqlite::Row<'_>> for ResourceTagEntryRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            tag_id: row.get("tag_id"),
            name: row.get("name"),
        }
    }
}

#[derive(Deserialize)]
struct FavoriteReq {
    resource_type: String,
    resource_id: i64,
}

#[derive(Serialize)]
struct FavoriteResp {
    id: i64,
    resource_type: String,
    resource_id: i64,
}

#[derive(Serialize)]
struct FavoriteEntry {
    id: i64,
    resource_type: String,
    resource_id: i64,
    name: Option<String>,
}

struct FavoriteEntryRow {
    id: i64,
    resource_type: String,
    resource_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for FavoriteEntryRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            resource_type: row.get("resource_type"),
            resource_id: row.get("resource_id"),
        }
    }
}

// ---------- helpers ----------

/// Checks that a resource (file or folder, non-deleted) exists.
/// ponytail: only "files"/"folders" resource types are supported; unknown
/// types are treated as not-found rather than a hard 400.
async fn resource_exists(state: &AppState, resource_type: &str, resource_id: i64) -> Result<bool, (StatusCode, &'static str)> {
    let table = match resource_type {
        "file" | "files" => "files",
        "folder" | "folders" => "folders",
        _ => return Ok(false),
    };
    let sql = format!("SELECT id FROM {table} WHERE id = $1 AND deleted_at IS NULL");
    let row: Option<IdRow> = state
        .db
        .query_map_optional(sql, params!(resource_id))
        .await
        .map_err(db_err)?;
    Ok(row.is_some())
}

async fn resource_name(state: &AppState, resource_type: &str, resource_id: i64) -> Option<String> {
    let table = match resource_type {
        "file" | "files" => "files",
        "folder" | "folders" => "folders",
        _ => return None,
    };
    let sql = format!("SELECT name FROM {table} WHERE id = $1");
    struct NameRow {
        name: String,
    }
    impl From<&mut hiqlite::Row<'_>> for NameRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self { name: row.get("name") }
        }
    }
    let fetched: Option<NameRow> = match state.db.query_map_optional(sql, params!(resource_id)).await {
        Ok(v) => v,
        Err(_) => None,
    };
    fetched.map(|r| r.name)
}

// ---------- tags ----------

async fn create_tag(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreateTagReq>,
) -> Result<Json<TagResp>, (StatusCode, &'static str)> {
    let created_at = chrono::Utc::now().to_rfc3339();
    let inserted: Result<IdRow, _> = state
        .db
        .execute_returning_map_one(
            "INSERT INTO tags (owner_token_id, name, created_at) VALUES ($1, $2, $3) RETURNING id",
            params!(ctx.id, &req.name, created_at),
        )
        .await;

    let id = match inserted {
        Ok(row) => row.id,
        Err(_) => {
            // Likely UNIQUE(owner_token_id, name) hit — look up existing.
            let existing: Option<IdRow> = state
                .db
                .query_map_optional(
                    "SELECT id FROM tags WHERE owner_token_id = $1 AND name = $2",
                    params!(ctx.id, &req.name),
                )
                .await
                .map_err(db_err)?;
            existing.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "db error"))?.id
        }
    };

    Ok(Json(TagResp { id, name: req.name }))
}

async fn list_tags(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<Vec<TagResp>>, (StatusCode, &'static str)> {
    let rows: Vec<TagRow> = state
        .db
        .query_map(
            "SELECT id, name FROM tags WHERE owner_token_id = $1",
            params!(ctx.id),
        )
        .await
        .map_err(db_err)?;
    Ok(Json(
        rows.into_iter().map(|r| TagResp { id: r.id, name: r.name }).collect(),
    ))
}

async fn delete_tag(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let row: Option<TagOwnerRow> = state
        .db
        .query_map_optional("SELECT owner_token_id FROM tags WHERE id = $1", params!(id))
        .await
        .map_err(db_err)?;
    let row = row.ok_or((StatusCode::NOT_FOUND, "tag not found"))?;
    if row.owner_token_id != ctx.id {
        return Err((StatusCode::FORBIDDEN, "not owner"));
    }

    state
        .db
        .execute("DELETE FROM resource_tags WHERE tag_id = $1", params!(id))
        .await
        .map_err(db_err)?;
    state
        .db
        .execute("DELETE FROM tags WHERE id = $1", params!(id))
        .await
        .map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------- resource-tags ----------

async fn attach_tag(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<ResourceTagReq>,
) -> Result<Json<ResourceTagResp>, (StatusCode, &'static str)> {
    let tag: Option<TagOwnerRow> = state
        .db
        .query_map_optional("SELECT owner_token_id FROM tags WHERE id = $1", params!(req.tag_id))
        .await
        .map_err(db_err)?;
    let tag = tag.ok_or((StatusCode::NOT_FOUND, "tag not found"))?;
    if tag.owner_token_id != ctx.id {
        return Err((StatusCode::FORBIDDEN, "not owner"));
    }

    if !resource_exists(&state, &req.resource_type, req.resource_id).await? {
        return Err((StatusCode::NOT_FOUND, "resource not found"));
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    let inserted: Result<IdRow, _> = state
        .db
        .execute_returning_map_one(
            "INSERT INTO resource_tags (resource_type, resource_id, tag_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
            params!(&req.resource_type, req.resource_id, req.tag_id, created_at),
        )
        .await;

    let id = match inserted {
        Ok(row) => row.id,
        Err(_) => {
            let existing: Option<IdRow> = state
                .db
                .query_map_optional(
                    "SELECT id FROM resource_tags WHERE resource_type = $1 AND resource_id = $2 AND tag_id = $3",
                    params!(&req.resource_type, req.resource_id, req.tag_id),
                )
                .await
                .map_err(db_err)?;
            existing.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "db error"))?.id
        }
    };

    Ok(Json(ResourceTagResp {
        id,
        resource_type: req.resource_type,
        resource_id: req.resource_id,
        tag_id: req.tag_id,
    }))
}

async fn list_resource_tags(
    State(state): State<AppState>,
    _ctx: TokenCtx,
    Query(q): Query<ResourceTagQuery>,
) -> Result<Json<Vec<ResourceTagEntry>>, (StatusCode, &'static str)> {
    let rows: Vec<ResourceTagEntryRow> = state
        .db
        .query_map(
            "SELECT rt.id AS id, rt.tag_id AS tag_id, t.name AS name \
             FROM resource_tags rt JOIN tags t ON t.id = rt.tag_id \
             WHERE rt.resource_type = $1 AND rt.resource_id = $2",
            params!(&q.resource_type, q.resource_id),
        )
        .await
        .map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|r| ResourceTagEntry {
                id: r.id,
                tag_id: r.tag_id,
                name: r.name,
            })
            .collect(),
    ))
}

async fn detach_tag(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let row: Option<ResourceTagOwnerRow> = state
        .db
        .query_map_optional(
            "SELECT t.owner_token_id AS tag_owner_token_id FROM resource_tags rt JOIN tags t ON t.id = rt.tag_id WHERE rt.id = $1",
            params!(id),
        )
        .await
        .map_err(db_err)?;
    let row = row.ok_or((StatusCode::NOT_FOUND, "resource tag not found"))?;
    if row.tag_owner_token_id != ctx.id {
        return Err((StatusCode::FORBIDDEN, "not owner"));
    }

    state
        .db
        .execute("DELETE FROM resource_tags WHERE id = $1", params!(id))
        .await
        .map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------- favorites ----------

async fn add_favorite(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<FavoriteReq>,
) -> Result<Json<FavoriteResp>, (StatusCode, &'static str)> {
    if !resource_exists(&state, &req.resource_type, req.resource_id).await? {
        return Err((StatusCode::NOT_FOUND, "resource not found"));
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    let inserted: Result<IdRow, _> = state
        .db
        .execute_returning_map_one(
            "INSERT INTO favorites (owner_token_id, resource_type, resource_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
            params!(ctx.id, &req.resource_type, req.resource_id, created_at),
        )
        .await;

    let id = match inserted {
        Ok(row) => row.id,
        Err(_) => {
            let existing: Option<IdRow> = state
                .db
                .query_map_optional(
                    "SELECT id FROM favorites WHERE owner_token_id = $1 AND resource_type = $2 AND resource_id = $3",
                    params!(ctx.id, &req.resource_type, req.resource_id),
                )
                .await
                .map_err(db_err)?;
            existing.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "db error"))?.id
        }
    };

    Ok(Json(FavoriteResp {
        id,
        resource_type: req.resource_type,
        resource_id: req.resource_id,
    }))
}

async fn list_favorites(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<Vec<FavoriteEntry>>, (StatusCode, &'static str)> {
    let rows: Vec<FavoriteEntryRow> = state
        .db
        .query_map(
            "SELECT id, resource_type, resource_id FROM favorites WHERE owner_token_id = $1",
            params!(ctx.id),
        )
        .await
        .map_err(db_err)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let name = resource_name(&state, &r.resource_type, r.resource_id).await;
        out.push(FavoriteEntry {
            id: r.id,
            resource_type: r.resource_type,
            resource_id: r.resource_id,
            name,
        });
    }
    Ok(Json(out))
}

async fn remove_favorite(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let row: Option<FavoriteOwnerRow> = state
        .db
        .query_map_optional("SELECT owner_token_id FROM favorites WHERE id = $1", params!(id))
        .await
        .map_err(db_err)?;
    let row = row.ok_or((StatusCode::NOT_FOUND, "favorite not found"))?;
    if row.owner_token_id != ctx.id {
        return Err((StatusCode::FORBIDDEN, "not owner"));
    }

    state
        .db
        .execute("DELETE FROM favorites WHERE id = $1", params!(id))
        .await
        .map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}
