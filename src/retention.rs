use axum::{extract::State, http::StatusCode, Json, Router};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{auth::TokenCtx, trash::purge_resource, AppState};

type ApiErr = (StatusCode, &'static str);

/// Hardcoded fallback when no policy row exists at all (global or per-user).
const DEFAULT_RETENTION_DAYS: i64 = 30;

/// Own schema for retention policy, run separately from db.rs's SCHEMA array
/// (see main.rs merge note) to avoid touching code other agents are editing.
pub async fn init_schema(db: &hiqlite::Client) {
    db.execute(
        r#"CREATE TABLE IF NOT EXISTS retention_policy (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_token_id INTEGER,
            trash_retention_days INTEGER NOT NULL DEFAULT 30,
            created_at TEXT NOT NULL,
            UNIQUE(owner_token_id)
        )"#,
        params!(),
    )
    .await
    .expect("retention schema init");
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/retention-policy",
            axum::routing::get(get_global_policy).put(put_global_policy),
        )
        .route(
            "/retention-policy/mine",
            axum::routing::get(get_my_policy).put(put_my_policy),
        )
}

#[derive(Serialize)]
struct PolicyResp {
    trash_retention_days: i64,
}

#[derive(Deserialize)]
struct PolicyReq {
    trash_retention_days: i64,
}

struct DaysRow {
    trash_retention_days: i64,
}
impl From<&mut hiqlite::Row<'_>> for DaysRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            trash_retention_days: row.get("trash_retention_days"),
        }
    }
}

async fn global_default_days(db: &hiqlite::Client) -> i64 {
    let row: Option<DaysRow> = db
        .query_map_optional(
            "SELECT trash_retention_days FROM retention_policy WHERE owner_token_id IS NULL",
            params!(),
        )
        .await
        .unwrap_or(None);
    row.map(|r| r.trash_retention_days)
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

async fn user_override_days(db: &hiqlite::Client, owner_token_id: i64) -> Option<i64> {
    let row: Option<DaysRow> = db
        .query_map_optional(
            "SELECT trash_retention_days FROM retention_policy WHERE owner_token_id = $1",
            params!(owner_token_id),
        )
        .await
        .unwrap_or(None);
    row.map(|r| r.trash_retention_days)
}

async fn upsert_policy(db: &hiqlite::Client, owner_token_id: Option<i64>, days: i64) -> Result<(), ApiErr> {
    let created_at = chrono::Utc::now().to_rfc3339();
    let sql = if owner_token_id.is_some() {
        "INSERT INTO retention_policy (owner_token_id, trash_retention_days, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT(owner_token_id) DO UPDATE SET trash_retention_days = excluded.trash_retention_days"
    } else {
        "INSERT INTO retention_policy (owner_token_id, trash_retention_days, created_at) VALUES (NULL, $2, $3) \
         ON CONFLICT(owner_token_id) DO UPDATE SET trash_retention_days = excluded.trash_retention_days"
    };
    db.execute(sql, params!(owner_token_id, days, created_at))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(())
}

async fn get_global_policy(State(state): State<AppState>, ctx: TokenCtx) -> Result<Json<PolicyResp>, ApiErr> {
    if !ctx.is_admin {
        return Err((StatusCode::FORBIDDEN, "admin only"));
    }
    Ok(Json(PolicyResp {
        trash_retention_days: global_default_days(&state.db).await,
    }))
}

async fn put_global_policy(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<PolicyReq>,
) -> Result<Json<PolicyResp>, ApiErr> {
    if !ctx.is_admin {
        return Err((StatusCode::FORBIDDEN, "admin only"));
    }
    upsert_policy(&state.db, None, req.trash_retention_days).await?;
    Ok(Json(PolicyResp {
        trash_retention_days: req.trash_retention_days,
    }))
}

// ponytail: MVP simplification — spec says "policy", the natural admin-control reading
// would restrict user overrides to admin-only too. Letting users tighten (or loosen)
// their own retention via PUT /retention-policy/mine is a reasonable self-service MVP
// scope, but if the intent was strict admin control, lock this route down to admins.
async fn get_my_policy(State(state): State<AppState>, ctx: TokenCtx) -> Result<Json<PolicyResp>, ApiErr> {
    let days = match user_override_days(&state.db, ctx.id).await {
        Some(d) => d,
        None => global_default_days(&state.db).await,
    };
    Ok(Json(PolicyResp { trash_retention_days: days }))
}

async fn put_my_policy(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<PolicyReq>,
) -> Result<Json<PolicyResp>, ApiErr> {
    upsert_policy(&state.db, Some(ctx.id), req.trash_retention_days).await?;
    Ok(Json(PolicyResp {
        trash_retention_days: req.trash_retention_days,
    }))
}

struct ExpiredRow {
    id: i64,
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for ExpiredRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            owner_token_id: row.get("owner_token_id"),
        }
    }
}

/// Sweeps `files`/`folders` past their owner's effective retention window and
/// permanently purges them, reusing `trash::purge_resource` (same chunk-refcount
/// release path as the manual `DELETE /trash/{id}` handler). Returns the count of
/// resources actually purged (folders skipped for still having live children don't
/// count). Deviates slightly from a `(db, storage)`-only signature to take the full
/// `AppState`, since `purge_resource` also needs `state.fts` to drop the fulltext
/// index entry for purged files.
pub async fn purge_expired_trash(state: &AppState) -> Result<u64, ApiErr> {
    let global_default = global_default_days(&state.db).await;
    let mut purged = 0u64;

    for table in ["folders", "files"] {
        let sql = format!(
            "SELECT {table}.id AS id, {table}.owner_token_id AS owner_token_id \
             FROM {table} WHERE {table}.deleted_at IS NOT NULL"
        );
        let rows: Vec<ExpiredRow> = state
            .db
            .query_map(sql, params!())
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

        for row in rows {
            let effective_days = match user_override_days(&state.db, row.owner_token_id).await {
                Some(d) => d,
                None => global_default,
            };

            let cutoff_sql = format!(
                "SELECT id FROM {table} WHERE id = $1 AND deleted_at IS NOT NULL \
                 AND deleted_at <= datetime('now', $2)"
            );
            let cutoff_arg = format!("-{effective_days} days");
            let expired: Option<crate::db::IdRow> = state
                .db
                .query_map_optional(cutoff_sql, params!(row.id, cutoff_arg))
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
            if expired.is_none() {
                continue;
            }

            if purge_resource(state, table, row.id).await? {
                purged += 1;
            }
        }
    }

    Ok(purged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::IdRow;

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

    async fn make_token(db: &hiqlite::Client) -> i64 {
        let row: IdRow = db
            .execute_returning_map_one(
                "INSERT INTO tokens (token, owner, created_at) VALUES ($1, 'u', $2) RETURNING id",
                params!(uuid::Uuid::new_v4().to_string(), chrono::Utc::now().to_rfc3339()),
            )
            .await
            .unwrap();
        row.id
    }

    struct RcRow {
        refcount: i64,
    }
    impl From<&mut hiqlite::Row<'_>> for RcRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self {
                refcount: row.get("refcount"),
            }
        }
    }

    /// Creates a file with one version/manifest chunk, soft-deleted at `deleted_at`.
    async fn make_deleted_file(state: &AppState, owner: i64, deleted_at: &str) -> (i64, String) {
        let now = chrono::Utc::now().to_rfc3339();
        let (manifest, size) = state.storage.write(b"retention test payload").await.unwrap();
        for h in &manifest {
            let existing: Option<RcRow> = state
                .db
                .query_map_optional("SELECT refcount FROM chunks WHERE hash = $1", params!(h))
                .await
                .unwrap();
            if existing.is_some() {
                state
                    .db
                    .execute("UPDATE chunks SET refcount = refcount + 1 WHERE hash = $1", params!(h))
                    .await
                    .unwrap();
            } else {
                state
                    .db
                    .execute(
                        "INSERT INTO chunks (hash, size, refcount) VALUES ($1, $2, 1)",
                        params!(h, size as i64),
                    )
                    .await
                    .unwrap();
            }
        }
        let file: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO files (name, owner_token_id, created_at, deleted_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!("f.txt", owner, now.clone(), deleted_at),
            )
            .await
            .unwrap();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        state
            .db
            .execute(
                "INSERT INTO file_versions (file_id, version_no, size, manifest, created_at) VALUES ($1, 1, $2, $3, $4)",
                params!(file.id, size as i64, manifest_json, now),
            )
            .await
            .unwrap();
        (file.id, manifest[0].clone())
    }

    #[tokio::test]
    async fn purges_files_past_retention_and_releases_chunks() {
        let (state, _dir) = setup().await;
        let owner = make_token(&state.db).await;
        let old = (chrono::Utc::now() - chrono::Duration::days(40)).to_rfc3339();
        let (file_id, hash) = make_deleted_file(&state, owner, &old).await;

        let purged = purge_expired_trash(&state).await.unwrap();

        assert_eq!(purged, 1);
        let gone: Option<crate::db::IdRow> = state
            .db
            .query_map_optional("SELECT id FROM files WHERE id = $1", params!(file_id))
            .await
            .unwrap();
        assert!(gone.is_none(), "file row should be purged");
        let rc: Option<RcRow> = state
            .db
            .query_map_optional("SELECT refcount FROM chunks WHERE hash = $1", params!(hash))
            .await
            .unwrap();
        assert!(rc.is_none(), "chunk should be released");
    }

    #[tokio::test]
    async fn does_not_purge_recently_deleted_file() {
        let (state, _dir) = setup().await;
        let owner = make_token(&state.db).await;
        let recent = chrono::Utc::now().to_rfc3339();
        let (file_id, _hash) = make_deleted_file(&state, owner, &recent).await;

        let purged = purge_expired_trash(&state).await.unwrap();

        assert_eq!(purged, 0);
        let still_there: Option<crate::db::IdRow> = state
            .db
            .query_map_optional("SELECT id FROM files WHERE id = $1", params!(file_id))
            .await
            .unwrap();
        assert!(still_there.is_some(), "recently-deleted file must survive the sweep");
    }
}
