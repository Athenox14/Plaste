use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, post},
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{require_admin, TokenCtx},
    db::IdRow,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/groups", post(create_group).get(list_groups))
        .route("/admin/groups/{id}", delete(delete_group))
        .route(
            "/admin/groups/{id}/members",
            post(add_member).get(list_members),
        )
        .route("/admin/groups/{id}/members/{token_id}", delete(remove_member))
}

type ApiErr = (StatusCode, &'static str);

#[derive(Deserialize)]
struct CreateGroupReq {
    name: String,
}

#[derive(Serialize)]
struct GroupResp {
    id: i64,
    name: String,
    created_at: String,
}

struct GroupRow {
    id: i64,
    name: String,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for GroupRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        }
    }
}

async fn create_group(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreateGroupReq>,
) -> Result<Json<GroupResp>, ApiErr> {
    require_admin(&ctx)?;
    let created_at = chrono::Utc::now().to_rfc3339();
    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO groups (name, created_at) VALUES ($1, $2) RETURNING id",
            params!(&req.name, created_at.clone()),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error (duplicate name?)"))?;

    Ok(Json(GroupResp {
        id: id_row.id,
        name: req.name,
        created_at,
    }))
}

async fn list_groups(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<Vec<GroupResp>>, ApiErr> {
    require_admin(&ctx)?;
    let rows: Vec<GroupRow> = state
        .db
        .query_map("SELECT id, name, created_at FROM groups", params!())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(Json(
        rows.into_iter()
            .map(|g| GroupResp {
                id: g.id,
                name: g.name,
                created_at: g.created_at,
            })
            .collect(),
    ))
}

async fn delete_group(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiErr> {
    require_admin(&ctx)?;
    state
        .db
        .execute("DELETE FROM group_members WHERE group_id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    state
        .db
        .execute("DELETE FROM groups WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AddMemberReq {
    token_id: i64,
}

async fn add_member(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(group_id): Path<i64>,
    Json(req): Json<AddMemberReq>,
) -> Result<impl IntoResponse, ApiErr> {
    require_admin(&ctx)?;
    let created_at = chrono::Utc::now().to_rfc3339();
    state
        .db
        .execute(
            "INSERT INTO group_members (group_id, token_id, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT(group_id, token_id) DO NOTHING",
            params!(group_id, req.token_id, created_at),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct MemberResp {
    token_id: i64,
    owner: String,
}

struct MemberRow {
    token_id: i64,
    owner: String,
}
impl From<&mut hiqlite::Row<'_>> for MemberRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            token_id: row.get("token_id"),
            owner: row.get("owner"),
        }
    }
}

async fn list_members(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(group_id): Path<i64>,
) -> Result<Json<Vec<MemberResp>>, ApiErr> {
    require_admin(&ctx)?;
    let rows: Vec<MemberRow> = state
        .db
        .query_map(
            "SELECT gm.token_id AS token_id, t.owner AS owner FROM group_members gm \
             JOIN tokens t ON t.id = gm.token_id WHERE gm.group_id = $1",
            params!(group_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(Json(
        rows.into_iter()
            .map(|m| MemberResp {
                token_id: m.token_id,
                owner: m.owner,
            })
            .collect(),
    ))
}

async fn remove_member(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path((group_id, token_id)): Path<(i64, i64)>,
) -> Result<impl IntoResponse, ApiErr> {
    require_admin(&ctx)?;
    state
        .db
        .execute(
            "DELETE FROM group_members WHERE group_id = $1 AND token_id = $2",
            params!(group_id, token_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(StatusCode::NO_CONTENT)
}
