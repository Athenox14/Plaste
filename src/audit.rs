use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{require_admin, TokenCtx},
    AppState,
};

type ApiErr = (StatusCode, &'static str);

/// Own table for this module; kept separate from db.rs's SCHEMA array (concurrent edits there).
pub async fn init_schema(db: &hiqlite::Client) {
    db.execute(
        r#"CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_token_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            detail TEXT,
            created_at TEXT NOT NULL
        )"#,
        params!(),
    )
    .await
    .expect("audit_log schema init");
}

/// Call after any mutating action. Fire-and-forget from the caller's perspective;
/// errors are logged, not propagated (audit logging should never fail the request).
pub async fn log(
    db: &hiqlite::Client,
    actor_token_id: i64,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<i64>,
    detail: Option<&str>,
) {
    let created_at = chrono::Utc::now().to_rfc3339();
    if let Err(e) = db
        .execute(
            "INSERT INTO audit_log (actor_token_id, action, resource_type, resource_id, detail, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            params!(actor_token_id, action, resource_type, resource_id, detail, created_at),
        )
        .await
    {
        tracing::warn!("audit::log failed: {e}");
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/audit-log", get(admin_list))
        .route("/audit-log/mine", get(mine_list))
}

fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(100).clamp(1, 1000)
}

#[derive(Deserialize)]
struct AdminQuery {
    limit: Option<i64>,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    actor_token_id: Option<i64>,
}

#[derive(Serialize)]
struct AdminEntry {
    id: i64,
    actor_owner: String,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    detail: Option<String>,
    created_at: String,
}

impl From<&mut hiqlite::Row<'_>> for AdminEntry {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            actor_owner: row.get("actor_owner"),
            action: row.get("action"),
            resource_type: row.get("resource_type"),
            resource_id: row.get("resource_id"),
            detail: row.get("detail"),
            created_at: row.get("created_at"),
        }
    }
}

async fn admin_list(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Query(q): Query<AdminQuery>,
) -> Result<Json<Vec<AdminEntry>>, ApiErr> {
    require_admin(&ctx)?;
    let limit = clamp_limit(q.limit);

    // ponytail: filters built as optional-equals via SQL `($n IS NULL OR col = $n)` rather than
    // dynamic query-string assembly — same params! call works whether filters are set or not.
    let rows: Vec<AdminEntry> = state
        .db
        .query_map(
            "SELECT a.id, t.owner AS actor_owner, a.action, a.resource_type, a.resource_id, a.detail, a.created_at \
             FROM audit_log a JOIN tokens t ON t.id = a.actor_token_id \
             WHERE ($1 IS NULL OR a.resource_type = $1) \
               AND ($2 IS NULL OR a.resource_id = $2) \
               AND ($3 IS NULL OR a.actor_token_id = $3) \
             ORDER BY a.created_at DESC LIMIT $4",
            params!(q.resource_type, q.resource_id, q.actor_token_id, limit),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(rows))
}

#[derive(Deserialize)]
struct MineQuery {
    limit: Option<i64>,
}

#[derive(Serialize)]
struct MineEntry {
    id: i64,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    detail: Option<String>,
    created_at: String,
}

impl From<&mut hiqlite::Row<'_>> for MineEntry {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            action: row.get("action"),
            resource_type: row.get("resource_type"),
            resource_id: row.get("resource_id"),
            detail: row.get("detail"),
            created_at: row.get("created_at"),
        }
    }
}

async fn mine_list(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Query(q): Query<MineQuery>,
) -> Result<Json<Vec<MineEntry>>, ApiErr> {
    let limit = clamp_limit(q.limit);
    let rows: Vec<MineEntry> = state
        .db
        .query_map(
            "SELECT id, action, resource_type, resource_id, detail, created_at \
             FROM audit_log WHERE actor_token_id = $1 ORDER BY created_at DESC LIMIT $2",
            params!(ctx.id, limit),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(rows))
}
