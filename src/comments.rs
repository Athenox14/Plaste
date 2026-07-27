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
        .route("/comments", axum::routing::post(create_comment).get(list_comments))
        .route("/comments/{id}", axum::routing::delete(delete_comment))
}

/// Schema for the comments feature, kept separate from db.rs's SCHEMA array
/// to avoid a merge conflict with a concurrent edit there.
pub async fn init_schema(db: &hiqlite::Client) {
    db.execute(
        r#"CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resource_type TEXT NOT NULL,
            resource_id INTEGER NOT NULL,
            author_token_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            mentions TEXT NOT NULL,
            created_at TEXT NOT NULL,
            deleted_at TEXT
        )"#,
        params!(),
    )
    .await
    .expect("comments schema init");
}

type ApiErr = (StatusCode, &'static str);

fn extract_mentions(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in body.split_whitespace() {
        if let Some(rest) = tok.strip_prefix('@') {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                .collect();
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

async fn resource_exists(state: &AppState, resource_type: &str, resource_id: i64) -> Result<bool, ApiErr> {
    let table = match resource_type {
        "file" => "files",
        "folder" => "folders",
        _ => return Ok(false),
    };
    let sql = format!("SELECT COUNT(*) AS count FROM {table} WHERE id = $1 AND deleted_at IS NULL");
    let mut row = state
        .db
        .query_raw_one(sql, params!(resource_id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let count: i64 = row.get("count");
    Ok(count > 0)
}

#[derive(Deserialize)]
struct CreateCommentReq {
    resource_type: String,
    resource_id: i64,
    body: String,
}

#[derive(Serialize)]
struct CommentResp {
    id: i64,
    body: String,
    mentions: Vec<String>,
    created_at: String,
}

async fn create_comment(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreateCommentReq>,
) -> Result<Json<CommentResp>, ApiErr> {
    if req.resource_type != "file" && req.resource_type != "folder" {
        return Err((StatusCode::BAD_REQUEST, "invalid resource_type"));
    }
    if !resource_exists(&state, &req.resource_type, req.resource_id).await? {
        return Err((StatusCode::NOT_FOUND, "resource not found"));
    }

    let mentions = extract_mentions(&req.body);
    let mentions_json =
        serde_json::to_string(&mentions).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "encode error"))?;
    let created_at = chrono::Utc::now().to_rfc3339();

    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO comments (resource_type, resource_id, author_token_id, body, mentions, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            params!(&req.resource_type, req.resource_id, ctx.id, &req.body, mentions_json, created_at.clone()),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(CommentResp {
        id: id_row.id,
        body: req.body,
        mentions,
        created_at,
    }))
}

#[derive(Deserialize)]
struct ListCommentsQuery {
    resource_type: String,
    resource_id: i64,
}

#[derive(Serialize)]
struct CommentListItem {
    id: i64,
    author_owner: String,
    body: String,
    mentions: Vec<String>,
    created_at: String,
}

struct CommentListRow {
    id: i64,
    author_owner: String,
    body: String,
    mentions: String,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for CommentListRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            author_owner: row.get("author_owner"),
            body: row.get("body"),
            mentions: row.get("mentions"),
            created_at: row.get("created_at"),
        }
    }
}

async fn list_comments(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Query(q): Query<ListCommentsQuery>,
) -> Result<Json<Vec<CommentListItem>>, ApiErr> {
    if !crate::acl::check_access(&state.db, &ctx, &q.resource_type, q.resource_id, crate::acl::Action::Read).await {
        return Err((StatusCode::NOT_FOUND, "resource not found"));
    }

    let rows: Vec<CommentListRow> = state
        .db
        .query_map(
            "SELECT c.id AS id, t.owner AS author_owner, c.body AS body, c.mentions AS mentions, c.created_at AS created_at \
             FROM comments c JOIN tokens t ON t.id = c.author_token_id \
             WHERE c.resource_type = $1 AND c.resource_id = $2 AND c.deleted_at IS NULL \
             ORDER BY c.created_at",
            params!(&q.resource_type, q.resource_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let items = rows
        .into_iter()
        .map(|r| {
            let mentions: Vec<String> = serde_json::from_str(&r.mentions).unwrap_or_default();
            CommentListItem {
                id: r.id,
                author_owner: r.author_owner,
                body: r.body,
                mentions,
                created_at: r.created_at,
            }
        })
        .collect();

    Ok(Json(items))
}

struct CommentOwnerRow {
    author_token_id: i64,
    deleted_at: Option<String>,
}
impl From<&mut hiqlite::Row<'_>> for CommentOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            author_token_id: row.get("author_token_id"),
            deleted_at: row.get("deleted_at"),
        }
    }
}

async fn delete_comment(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiErr> {
    let row: Option<CommentOwnerRow> = state
        .db
        .query_map_optional(
            "SELECT author_token_id, deleted_at FROM comments WHERE id = $1",
            params!(id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let row = row.ok_or((StatusCode::NOT_FOUND, "comment not found"))?;
    if row.deleted_at.is_some() {
        return Err((StatusCode::NOT_FOUND, "comment not found"));
    }
    if row.author_token_id != ctx.id && !ctx.is_admin {
        return Err((StatusCode::FORBIDDEN, "not author"));
    }

    let deleted_at = chrono::Utc::now().to_rfc3339();
    state
        .db
        .execute(
            "UPDATE comments SET deleted_at = $1 WHERE id = $2",
            params!(deleted_at, id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(StatusCode::NO_CONTENT)
}
