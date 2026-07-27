use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json, Router,
};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{auth::TokenCtx, db::IdRow, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/shares", axum::routing::post(create_share).get(list_shares))
        .route("/shares/{id}", axum::routing::delete(revoke_share))
        .route("/public/shares/{share_token}", axum::routing::get(resolve_public_share))
        .route(
            "/public/shares/{share_token}/download",
            axum::routing::get(download_public_share),
        )
        .route(
            "/permissions",
            axum::routing::post(create_permission).get(list_permissions),
        )
        .route("/permissions/{id}", axum::routing::delete(revoke_permission))
}

type ApiErr = (StatusCode, &'static str);

// ---------- shared row types ----------

struct ShareRow {
    id: i64,
    resource_type: String,
    resource_id: i64,
    owner_token_id: i64,
    share_token: String,
    password_hash: Option<String>,
    expires_at: Option<String>,
    permission: String,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for ShareRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            resource_type: row.get("resource_type"),
            resource_id: row.get("resource_id"),
            owner_token_id: row.get("owner_token_id"),
            share_token: row.get("share_token"),
            password_hash: row.get("password_hash"),
            expires_at: row.get("expires_at"),
            permission: row.get("permission"),
            created_at: row.get("created_at"),
        }
    }
}

struct PermissionRow {
    id: i64,
    resource_type: String,
    resource_id: i64,
    /// Sentinel `0` (not a real token id, autoincrement starts at 1) means "no direct
    /// grantee" — this grant is group-based instead; see `grantee_group_id`.
    grantee_token_id: i64,
    grantee_group_id: Option<i64>,
    permission: String,
    granted_by_token_id: i64,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for PermissionRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            resource_type: row.get("resource_type"),
            resource_id: row.get("resource_id"),
            grantee_token_id: row.get("grantee_token_id"),
            grantee_group_id: row.get("grantee_group_id"),
            permission: row.get("permission"),
            granted_by_token_id: row.get("granted_by_token_id"),
            created_at: row.get("created_at"),
        }
    }
}

/// Confirms `resource_type`/`resource_id` exists (in `files`/`folders`, not soft-deleted)
/// and returns its owner_token_id, or 404/400.
async fn resource_owner(
    state: &AppState,
    resource_type: &str,
    resource_id: i64,
) -> Result<i64, ApiErr> {
    let owner: Option<IdRow> = match resource_type {
        "file" => {
            state
                .db
                .query_map_optional(
                    "SELECT owner_token_id AS id FROM files WHERE id = $1 AND deleted_at IS NULL",
                    params!(resource_id),
                )
                .await
        }
        "folder" => {
            state
                .db
                .query_map_optional(
                    "SELECT owner_token_id AS id FROM folders WHERE id = $1 AND deleted_at IS NULL",
                    params!(resource_id),
                )
                .await
        }
        _ => return Err((StatusCode::BAD_REQUEST, "resource_type must be 'file' or 'folder'")),
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    owner.map(|r| r.id).ok_or((StatusCode::NOT_FOUND, "resource not found"))
}

fn check_owner_or_admin(ctx: &TokenCtx, owner_token_id: i64) -> Result<(), ApiErr> {
    if ctx.is_admin || ctx.id == owner_token_id {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "not owner"))
    }
}

fn valid_permission(p: &str) -> bool {
    matches!(p, "read" | "write" | "comment")
}

// ---------- POST/GET/DELETE /shares ----------

#[derive(Deserialize)]
struct CreateShareReq {
    resource_type: String,
    resource_id: i64,
    password: Option<String>,
    expires_at: Option<String>,
    permission: String,
}

#[derive(Serialize)]
struct CreateShareResp {
    id: i64,
    share_token: String,
    permission: String,
    expires_at: Option<String>,
}

async fn create_share(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreateShareReq>,
) -> Result<Json<CreateShareResp>, ApiErr> {
    if !valid_permission(&req.permission) {
        return Err((StatusCode::BAD_REQUEST, "invalid permission"));
    }
    let owner_token_id = resource_owner(&state, &req.resource_type, req.resource_id).await?;
    check_owner_or_admin(&ctx, owner_token_id)?;

    let share_token = uuid::Uuid::new_v4().to_string();
    // ponytail: blake3 hash, no salt — MVP password-protected links, not a login system.
    let password_hash = req.password.as_deref().map(|p| blake3::hash(p.as_bytes()).to_hex().to_string());
    let created_at = chrono::Utc::now().to_rfc3339();

    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO shares (resource_type, resource_id, owner_token_id, share_token, password_hash, expires_at, permission, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
            params!(
                &req.resource_type,
                req.resource_id,
                ctx.id,
                &share_token,
                password_hash,
                &req.expires_at,
                &req.permission,
                created_at
            ),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(&state.db, ctx.id, "share.create", Some("share"), Some(id_row.id), None).await;

    Ok(Json(CreateShareResp {
        id: id_row.id,
        share_token,
        permission: req.permission,
        expires_at: req.expires_at,
    }))
}

#[derive(Serialize)]
struct ShareResp {
    id: i64,
    share_token: String,
    resource_type: String,
    resource_id: i64,
    permission: String,
    expires_at: Option<String>,
    created_at: String,
}

async fn list_shares(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<Vec<ShareResp>>, ApiErr> {
    let rows: Vec<ShareRow> = state
        .db
        .query_map(
            "SELECT id, resource_type, resource_id, owner_token_id, share_token, password_hash, expires_at, permission, created_at \
             FROM shares WHERE owner_token_id = $1",
            params!(ctx.id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(
        rows.into_iter()
            .map(|s| ShareResp {
                id: s.id,
                share_token: s.share_token,
                resource_type: s.resource_type,
                resource_id: s.resource_id,
                permission: s.permission,
                expires_at: s.expires_at,
                created_at: s.created_at,
            })
            .collect(),
    ))
}

async fn revoke_share(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiErr> {
    let share: Option<ShareRow> = state
        .db
        .query_map_optional(
            "SELECT id, resource_type, resource_id, owner_token_id, share_token, password_hash, expires_at, permission, created_at \
             FROM shares WHERE id = $1",
            params!(id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let share = share.ok_or((StatusCode::NOT_FOUND, "share not found"))?;
    check_owner_or_admin(&ctx, share.owner_token_id)?;

    state
        .db
        .execute("DELETE FROM shares WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    crate::audit::log(&state.db, ctx.id, "share.revoke", Some("share"), Some(id), None).await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- public share resolution ----------

#[derive(Deserialize)]
struct PublicShareQuery {
    password: Option<String>,
}

/// Looks up a share by token, enforcing expiry/password. Shared by resolve + download.
async fn load_valid_share(
    state: &AppState,
    share_token: &str,
    password: Option<&str>,
) -> Result<ShareRow, ApiErr> {
    let share: Option<ShareRow> = state
        .db
        .query_map_optional(
            "SELECT id, resource_type, resource_id, owner_token_id, share_token, password_hash, expires_at, permission, created_at \
             FROM shares WHERE share_token = $1",
            params!(share_token),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let share = share.ok_or((StatusCode::NOT_FOUND, "share not found"))?;

    if let Some(expires_at) = &share.expires_at {
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
            if expiry < chrono::Utc::now() {
                return Err((StatusCode::GONE, "share expired"));
            }
        }
    }

    if let Some(hash) = &share.password_hash {
        let ok = password
            .map(|p| &blake3::hash(p.as_bytes()).to_hex().to_string() == hash)
            .unwrap_or(false);
        if !ok {
            return Err((StatusCode::UNAUTHORIZED, "password required or incorrect"));
        }
    }

    Ok(share)
}

#[derive(Serialize)]
struct PublicFileInfo {
    kind: &'static str,
    name: String,
    size: i64,
}

#[derive(Serialize)]
struct PublicFolderInfo {
    kind: &'static str,
    name: String,
    children: Vec<String>,
}

async fn resolve_public_share(
    State(state): State<AppState>,
    Path(share_token): Path<String>,
    Query(q): Query<PublicShareQuery>,
) -> Result<impl IntoResponse, ApiErr> {
    let share = load_valid_share(&state, &share_token, q.password.as_deref()).await?;

    if share.resource_type == "file" {
        struct FileInfoRow {
            name: String,
            size: i64,
        }
        impl From<&mut hiqlite::Row<'_>> for FileInfoRow {
            fn from(row: &mut hiqlite::Row<'_>) -> Self {
                Self {
                    name: row.get("name"),
                    size: row.get("size"),
                }
            }
        }
        let info: Option<FileInfoRow> = state
            .db
            .query_map_optional(
                "SELECT f.name AS name, COALESCE(v.size, 0) AS size FROM files f \
                 LEFT JOIN file_versions v ON v.id = f.current_version_id \
                 WHERE f.id = $1 AND f.deleted_at IS NULL",
                params!(share.resource_id),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        let info = info.ok_or((StatusCode::NOT_FOUND, "shared resource not found"))?;
        Ok(Json(PublicFileInfo {
            kind: "file",
            name: info.name,
            size: info.size,
        })
        .into_response())
    } else {
        struct NameRow {
            name: String,
        }
        impl From<&mut hiqlite::Row<'_>> for NameRow {
            fn from(row: &mut hiqlite::Row<'_>) -> Self {
                Self { name: row.get("name") }
            }
        }
        let folder: Option<NameRow> = state
            .db
            .query_map_optional(
                "SELECT name FROM folders WHERE id = $1 AND deleted_at IS NULL",
                params!(share.resource_id),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        let folder = folder.ok_or((StatusCode::NOT_FOUND, "shared resource not found"))?;

        let mut children: Vec<String> = state
            .db
            .query_map::<NameRow, _>(
                "SELECT name FROM folders WHERE parent_id = $1 AND deleted_at IS NULL",
                params!(share.resource_id),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
            .into_iter()
            .map(|r| r.name)
            .collect();
        let file_children: Vec<NameRow> = state
            .db
            .query_map(
                "SELECT name FROM files WHERE folder_id = $1 AND deleted_at IS NULL",
                params!(share.resource_id),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        children.extend(file_children.into_iter().map(|r| r.name));

        Ok(Json(PublicFolderInfo {
            kind: "folder",
            name: folder.name,
            children,
        })
        .into_response())
    }
}

async fn download_public_share(
    State(state): State<AppState>,
    Path(share_token): Path<String>,
    Query(q): Query<PublicShareQuery>,
) -> Result<impl IntoResponse, ApiErr> {
    let share = load_valid_share(&state, &share_token, q.password.as_deref()).await?;
    if share.resource_type != "file" {
        return Err((StatusCode::BAD_REQUEST, "share does not point to a file"));
    }

    struct FileRow {
        name: String,
        current_version_id: Option<i64>,
    }
    impl From<&mut hiqlite::Row<'_>> for FileRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self {
                name: row.get("name"),
                current_version_id: row.get("current_version_id"),
            }
        }
    }
    let file: Option<FileRow> = state
        .db
        .query_map_optional(
            "SELECT name, current_version_id FROM files WHERE id = $1 AND deleted_at IS NULL",
            params!(share.resource_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let file = file.ok_or((StatusCode::NOT_FOUND, "shared file not found"))?;
    let name = file.name;
    let version_id = file
        .current_version_id
        .ok_or((StatusCode::NOT_FOUND, "no current version"))?;

    struct ManifestRow {
        manifest: String,
    }
    impl From<&mut hiqlite::Row<'_>> for ManifestRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self { manifest: row.get("manifest") }
        }
    }
    let version: Option<ManifestRow> = state
        .db
        .query_map_optional(
            "SELECT manifest FROM file_versions WHERE id = $1",
            params!(version_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let version = version.ok_or((StatusCode::NOT_FOUND, "version not found"))?;

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
            format!("attachment; filename=\"{}\"", name),
        ),
    ];

    Ok((headers, data))
}

// ---------- permissions ----------

#[derive(Deserialize)]
struct CreatePermissionReq {
    resource_type: String,
    resource_id: i64,
    #[serde(default)]
    grantee_owner: Option<String>,
    #[serde(default)]
    grantee_group: Option<String>,
    permission: String,
}

#[derive(Serialize)]
struct PermissionResp {
    id: i64,
    resource_type: String,
    resource_id: i64,
    grantee_token_id: Option<i64>,
    grantee_group_id: Option<i64>,
    permission: String,
    granted_by_token_id: i64,
    created_at: String,
}

async fn create_permission(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreatePermissionReq>,
) -> Result<Json<PermissionResp>, ApiErr> {
    if !valid_permission(&req.permission) {
        return Err((StatusCode::BAD_REQUEST, "invalid permission"));
    }
    if req.grantee_owner.is_some() == req.grantee_group.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "exactly one of grantee_owner/grantee_group must be provided",
        ));
    }
    let owner_token_id = resource_owner(&state, &req.resource_type, req.resource_id).await?;
    check_owner_or_admin(&ctx, owner_token_id)?;

    let created_at = chrono::Utc::now().to_rfc3339();

    if let Some(grantee_owner) = &req.grantee_owner {
        let grantee: Option<IdRow> = state
            .db
            .query_map_optional("SELECT id FROM tokens WHERE owner = $1", params!(grantee_owner))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        let grantee = grantee.ok_or((StatusCode::NOT_FOUND, "grantee owner not found"))?;

        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO permissions (resource_type, resource_id, grantee_token_id, permission, granted_by_token_id, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT(resource_type, resource_id, grantee_token_id) \
                 DO UPDATE SET permission = excluded.permission, granted_by_token_id = excluded.granted_by_token_id \
                 RETURNING id",
                params!(
                    &req.resource_type,
                    req.resource_id,
                    grantee.id,
                    &req.permission,
                    ctx.id,
                    created_at.clone()
                ),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

        crate::audit::log(&state.db, ctx.id, "permission.grant", Some("permission"), Some(id_row.id), None).await;

        return Ok(Json(PermissionResp {
            id: id_row.id,
            resource_type: req.resource_type,
            resource_id: req.resource_id,
            grantee_token_id: Some(grantee.id),
            grantee_group_id: None,
            permission: req.permission,
            granted_by_token_id: ctx.id,
            created_at,
        }));
    }

    // grantee_group path
    let group_name = req.grantee_group.as_ref().unwrap();
    let group: Option<IdRow> = state
        .db
        .query_map_optional("SELECT id FROM groups WHERE name = $1", params!(group_name))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let group = group.ok_or((StatusCode::NOT_FOUND, "group not found"))?;

    // ponytail: the pre-existing unique index is on (resource_type, resource_id,
    // grantee_token_id), so with the 0-sentinel two different groups granted on the
    // *same* resource would collide. Add a matching unique index on
    // (resource_type, resource_id, grantee_group_id) if multi-group grants per
    // resource are needed later.
    // grantee_token_id is NOT NULL (pre-existing schema); use sentinel 0
    // (token autoincrement starts at 1, so it never collides with a real token id) to
    // mean "no direct grantee" for group-based rows, rather than an ALTER TABLE column
    // rebuild. acl.rs's direct-grant lookup filters on ctx.id, which is never 0.
    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO permissions (resource_type, resource_id, grantee_token_id, grantee_group_id, permission, granted_by_token_id, created_at) \
             VALUES ($1, $2, 0, $3, $4, $5, $6) \
             RETURNING id",
            params!(
                &req.resource_type,
                req.resource_id,
                group.id,
                &req.permission,
                ctx.id,
                created_at.clone()
            ),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(&state.db, ctx.id, "permission.grant", Some("permission"), Some(id_row.id), None).await;

    Ok(Json(PermissionResp {
        id: id_row.id,
        resource_type: req.resource_type,
        resource_id: req.resource_id,
        grantee_token_id: None,
        grantee_group_id: Some(group.id),
        permission: req.permission,
        granted_by_token_id: ctx.id,
        created_at,
    }))
}

#[derive(Deserialize)]
struct ListPermissionsQuery {
    resource_type: String,
    resource_id: i64,
}

async fn list_permissions(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Query(q): Query<ListPermissionsQuery>,
) -> Result<Json<Vec<PermissionResp>>, ApiErr> {
    let owner_token_id = resource_owner(&state, &q.resource_type, q.resource_id).await?;
    check_owner_or_admin(&ctx, owner_token_id)?;

    let rows: Vec<PermissionRow> = state
        .db
        .query_map(
            "SELECT id, resource_type, resource_id, grantee_token_id, grantee_group_id, permission, granted_by_token_id, created_at \
             FROM permissions WHERE resource_type = $1 AND resource_id = $2",
            params!(&q.resource_type, q.resource_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(
        rows.into_iter()
            .map(|p| PermissionResp {
                id: p.id,
                resource_type: p.resource_type,
                resource_id: p.resource_id,
                grantee_token_id: if p.grantee_token_id == 0 { None } else { Some(p.grantee_token_id) },
                grantee_group_id: p.grantee_group_id,
                permission: p.permission,
                granted_by_token_id: p.granted_by_token_id,
                created_at: p.created_at,
            })
            .collect(),
    ))
}

async fn revoke_permission(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiErr> {
    let perm: Option<PermissionRow> = state
        .db
        .query_map_optional(
            "SELECT id, resource_type, resource_id, grantee_token_id, grantee_group_id, permission, granted_by_token_id, created_at \
             FROM permissions WHERE id = $1",
            params!(id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let perm = perm.ok_or((StatusCode::NOT_FOUND, "permission not found"))?;
    let owner_token_id = resource_owner(&state, &perm.resource_type, perm.resource_id).await?;
    check_owner_or_admin(&ctx, owner_token_id)?;

    state
        .db
        .execute("DELETE FROM permissions WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    crate::audit::log(&state.db, ctx.id, "permission.revoke", Some("permission"), Some(id), None).await;
    Ok(StatusCode::NO_CONTENT)
}
