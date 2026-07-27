//! Admin-configurable storage backend definitions (REST). See also `graphql.rs` for the
//! GraphQL surface and `storage.rs` for `ChunkStore::activate_backend` (the actual runtime
//! swap mechanism).
//!
//! Important clarification (documented here and repeated in the schema comment): CIFS/NFS
//! is NOT a distinct protocol Plaste implements. A "CIFS/NFS" backend is just an `fs`-kind
//! backend whose `config.path` happens to be a local mount point where the OS has already
//! mounted a network share. Plaste never speaks SMB/NFS itself — it only ever does local
//! filesystem I/O via opendal's `services::Fs`, same as local-disk. "Local disk" and
//! "mounted network share" are indistinguishable to Plaste; the distinction is purely at the
//! OS/ops level (whatever `path` the admin points it at).
//!
//! NOTE (deliberate MVP scope boundary, mirrors the hot/cold tiering limitation): activating
//! a backend affects NEW writes only. Chunks already stored under the previously-active
//! backend are NOT migrated automatically — see `ChunkStore::activate_backend`.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{auth::{require_admin, TokenCtx}, db::IdRow, AppState};

/// Own schema, run separately from db.rs's SCHEMA array (same pattern as tags.rs/tiering.rs).
pub async fn init_schema(db: &hiqlite::Client) {
    const SCHEMA: &[&str] = &[r#"CREATE TABLE IF NOT EXISTS storage_backends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        kind TEXT NOT NULL,
        config TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )"#];
    for stmt in SCHEMA {
        db.execute(*stmt, params!()).await.expect("storage_backends schema migration");
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/storage-backends", post(create_backend).get(list_backends))
        .route("/admin/storage-backends/{id}", axum::routing::delete(delete_backend))
        .route("/admin/storage-backends/{id}/activate", post(activate_backend))
}

#[derive(Deserialize)]
struct CreateBackendReq {
    name: String,
    kind: String,
    config: serde_json::Value,
}

#[derive(Serialize)]
struct BackendResp {
    id: i64,
    name: String,
    kind: String,
    config: serde_json::Value,
    is_active: bool,
    created_at: String,
}

struct BackendRow {
    id: i64,
    name: String,
    kind: String,
    config: String,
    is_active: bool,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for BackendRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            kind: row.get("kind"),
            config: row.get("config"),
            is_active: row.get::<i64>("is_active") != 0,
            created_at: row.get("created_at"),
        }
    }
}

/// Validates that `config` has the right shape for `kind`, returning a normalized error
/// message otherwise. Doesn't build an `Operator` (that only happens on activate) — just
/// checks the JSON has the fields `storage::build_operator` will need.
fn validate_config(kind: &str, config: &serde_json::Value) -> Result<(), &'static str> {
    let has_str = |k: &str| config.get(k).and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty());
    match kind {
        "fs" => {
            if has_str("path") {
                Ok(())
            } else {
                Err("fs config requires non-empty 'path' (for CIFS/NFS this is the local OS mount point of the share)")
            }
        }
        "s3" => {
            if has_str("bucket") && has_str("region") && has_str("access_key") && has_str("secret_key") {
                Ok(())
            } else {
                Err("s3 config requires 'bucket', 'region', 'access_key', 'secret_key' ('endpoint' optional)")
            }
        }
        _ => Err("kind must be 'fs' or 's3'"),
    }
}

/// Redacts `access_key`/`secret_key` from an s3 config before it ever goes back out over the
/// API. fs configs have no secrets so pass through unchanged.
fn redact_config(kind: &str, config: &str) -> serde_json::Value {
    let mut v: serde_json::Value = serde_json::from_str(config).unwrap_or(serde_json::json!({}));
    if kind == "s3" {
        if let Some(obj) = v.as_object_mut() {
            if obj.contains_key("access_key") {
                obj.insert("access_key".into(), serde_json::json!("<redacted>"));
            }
            if obj.contains_key("secret_key") {
                obj.insert("secret_key".into(), serde_json::json!("<redacted>"));
            }
        }
    }
    v
}

impl From<BackendRow> for BackendResp {
    fn from(r: BackendRow) -> Self {
        BackendResp {
            id: r.id,
            name: r.name,
            config: redact_config(&r.kind, &r.config),
            kind: r.kind,
            is_active: r.is_active,
            created_at: r.created_at,
        }
    }
}

async fn create_backend(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreateBackendReq>,
) -> Result<Json<BackendResp>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    validate_config(&req.kind, &req.config).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let config_str = serde_json::to_string(&req.config).map_err(|_| (StatusCode::BAD_REQUEST, "invalid config"))?;
    let created_at = chrono::Utc::now().to_rfc3339();

    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO storage_backends (name, kind, config, is_active, created_at) VALUES ($1, $2, $3, 0, $4) RETURNING id",
            params!(&req.name, &req.kind, &config_str, &created_at),
        )
        .await
        .map_err(|_| (StatusCode::CONFLICT, "backend name already exists or db error"))?;

    crate::audit::log(&state.db, ctx.id, "storage_backend.create", Some("storage_backend"), Some(id_row.id), None).await;

    Ok(Json(BackendResp {
        id: id_row.id,
        name: req.name,
        config: redact_config(&req.kind, &config_str),
        kind: req.kind,
        is_active: false,
        created_at,
    }))
}

async fn list_backends(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<Vec<BackendResp>>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let rows: Vec<BackendRow> = state
        .db
        .query_map("SELECT id, name, kind, config, is_active, created_at FROM storage_backends", params!())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn delete_backend(
    State(state): State<AppState>,
    ctx: TokenCtx,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let row: Option<BackendRow> = state
        .db
        .query_map_optional("SELECT id, name, kind, config, is_active, created_at FROM storage_backends WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let row = row.ok_or((StatusCode::NOT_FOUND, "backend not found"))?;
    if row.is_active {
        return Err((StatusCode::CONFLICT, "cannot delete the active backend; activate another backend first"));
    }
    state.db.execute("DELETE FROM storage_backends WHERE id = $1", params!(id)).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    crate::audit::log(&state.db, ctx.id, "storage_backend.delete", Some("storage_backend"), Some(id), None).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn activate_backend(
    State(state): State<AppState>,
    ctx: TokenCtx,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<BackendResp>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let row: Option<BackendRow> = state
        .db
        .query_map_optional("SELECT id, name, kind, config, is_active, created_at FROM storage_backends WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let row = row.ok_or((StatusCode::NOT_FOUND, "backend not found"))?;

    let config: serde_json::Value = serde_json::from_str(&row.config).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "stored config corrupt"))?;
    state
        .storage
        .activate_backend(&row.kind, &config)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "failed to build/activate backend (bad config?)"))?;

    state.db.execute("UPDATE storage_backends SET is_active = 0", params!()).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    state.db.execute("UPDATE storage_backends SET is_active = 1 WHERE id = $1", params!(id)).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(&state.db, ctx.id, "storage_backend.activate", Some("storage_backend"), Some(id), None).await;

    Ok(Json(BackendResp {
        id: row.id,
        name: row.name,
        config: redact_config(&row.kind, &row.config),
        kind: row.kind,
        is_active: true,
        created_at: row.created_at,
    }))
}

#[cfg(test)]
mod tests {
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

    async fn make_admin_token(db: &hiqlite::Client) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        db.execute(
            "INSERT INTO tokens (token, owner, is_admin, created_at) VALUES ($1, 'admin', 1, $2)",
            params!(&token, chrono::Utc::now().to_rfc3339()),
        )
        .await
        .unwrap();
        token
    }

    async fn call(app: Router<AppState>, state: AppState, method: &str, uri: &str, token: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn create_fs_backend_and_list_no_secrets() {
        let (state, dir) = setup().await;
        let admin = make_admin_token(&state.db).await;
        let path = dir.path().join("fs-backend-a").to_string_lossy().to_string();

        let (status, created) = call(
            router(),
            state.clone(),
            "POST",
            "/admin/storage-backends",
            &admin,
            &format!(r#"{{"name":"fs-a","kind":"fs","config":{{"path":"{}"}}}}"#, path.replace('\\', "\\\\")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{created:?}");
        assert_eq!(created["is_active"], false);
        assert_eq!(created["config"]["path"], path);

        let (status, list) = call(router(), state.clone(), "GET", "/admin/storage-backends", &admin, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn create_s3_backend_redacts_secrets_in_list() {
        let (state, _dir) = setup().await;
        let admin = make_admin_token(&state.db).await;

        let (status, _created) = call(
            router(),
            state.clone(),
            "POST",
            "/admin/storage-backends",
            &admin,
            r#"{"name":"s3-a","kind":"s3","config":{"bucket":"b","region":"us-east-1","endpoint":"http://localhost:9000","access_key":"AKIASECRET","secret_key":"supersecret"}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, list) = call(router(), state.clone(), "GET", "/admin/storage-backends", &admin, "").await;
        assert_eq!(status, StatusCode::OK);
        let row = &list.as_array().unwrap()[0];
        assert_eq!(row["config"]["access_key"], "<redacted>");
        assert_eq!(row["config"]["secret_key"], "<redacted>");
        assert_eq!(row["config"]["bucket"], "b");
    }

    #[tokio::test]
    async fn activate_swaps_chunk_store_writes_to_new_path_and_delete_active_rejected() {
        let (state, dir) = setup().await;
        let admin = make_admin_token(&state.db).await;

        // Write a chunk before activating anything: lands in the original (setup()) dir.
        let (manifest_before, _) = state.storage.write(b"before activation data").await.unwrap();
        let hash_before = manifest_before[0].clone();
        let orig_dir = dir.path().join("chunks");
        assert!(orig_dir.join(&hash_before[0..2]).join(&hash_before).exists());

        let new_dir = dir.path().join("fs-backend-b");
        let (status, created) = call(
            router(),
            state.clone(),
            "POST",
            "/admin/storage-backends",
            &admin,
            &format!(r#"{{"name":"fs-b","kind":"fs","config":{{"path":"{}"}}}}"#, new_dir.to_string_lossy().replace('\\', "\\\\")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let id = created["id"].as_str().map(|s| s.to_string()).unwrap_or_else(|| created["id"].to_string());
        let id = id.trim_matches('"');

        // Deleting is refused before activation is irrelevant here (not active yet) — check
        // active-delete rejection after activating instead.
        let (status, _activated) = call(
            router(),
            state.clone(),
            "POST",
            &format!("/admin/storage-backends/{id}/activate"),
            &admin,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Deleting the now-active backend must be rejected.
        let (status, _) = call(router(), state.clone(), "DELETE", &format!("/admin/storage-backends/{id}"), &admin, "").await;
        assert_eq!(status, StatusCode::CONFLICT);

        // New write after activation must land in the new dir, not the old one.
        let (manifest_after, _) = state.storage.write(b"after activation data, different content").await.unwrap();
        let hash_after = manifest_after[0].clone();
        assert!(new_dir.join(&hash_after[0..2]).join(&hash_after).exists(), "post-activation chunk should be in new backend dir");
        assert!(!orig_dir.join(&hash_after[0..2]).join(&hash_after).exists(), "post-activation chunk should NOT be in old backend dir");
    }
}
