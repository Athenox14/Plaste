use async_graphql::{Context, EmptySubscription, Object, Result as GqlResult, Schema, SimpleObject, ID};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
    response::{Html, IntoResponse},
    Router,
};
use hiqlite::params;

use crate::{acl, auth::TokenCtx, db::IdRow, AppState};

pub type PlasteSchema = Schema<Query, Mutation, EmptySubscription>;

#[derive(SimpleObject)]
pub struct Folder {
    id: ID,
    name: String,
    parent_id: Option<ID>,
    created_at: String,
}

struct FolderRow {
    id: i64,
    name: String,
    parent_id: Option<i64>,
    created_at: String,
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for FolderRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            parent_id: row.get("parent_id"),
            created_at: row.get("created_at"),
            owner_token_id: row.get("owner_token_id"),
        }
    }
}
impl From<FolderRow> for Folder {
    fn from(r: FolderRow) -> Self {
        Folder {
            id: ID(r.id.to_string()),
            name: r.name,
            parent_id: r.parent_id.map(|p| ID(p.to_string())),
            created_at: r.created_at,
        }
    }
}

#[derive(SimpleObject)]
pub struct File {
    id: ID,
    name: String,
    folder_id: Option<ID>,
    size: i64,
    created_at: String,
    current_version_no: Option<i64>,
}

struct FileRow {
    id: i64,
    name: String,
    folder_id: Option<i64>,
    size: i64,
    created_at: String,
    current_version_no: Option<i64>,
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for FileRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            folder_id: row.get("folder_id"),
            size: row.get("size"),
            created_at: row.get("created_at"),
            current_version_no: row.get("current_version_no"),
            owner_token_id: row.get("owner_token_id"),
        }
    }
}
impl From<FileRow> for File {
    fn from(r: FileRow) -> Self {
        File {
            id: ID(r.id.to_string()),
            name: r.name,
            folder_id: r.folder_id.map(|f| ID(f.to_string())),
            size: r.size,
            created_at: r.created_at,
            current_version_no: r.current_version_no,
        }
    }
}

#[derive(SimpleObject)]
pub struct FileVersion {
    id: ID,
    version_no: i64,
    size: i64,
    created_at: String,
}

struct FileVersionRow {
    id: i64,
    version_no: i64,
    size: i64,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for FileVersionRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            version_no: row.get("version_no"),
            size: row.get("size"),
            created_at: row.get("created_at"),
        }
    }
}
impl From<FileVersionRow> for FileVersion {
    fn from(r: FileVersionRow) -> Self {
        FileVersion {
            id: ID(r.id.to_string()),
            version_no: r.version_no,
            size: r.size,
            created_at: r.created_at,
        }
    }
}

#[derive(SimpleObject)]
pub struct SearchResult {
    folders: Vec<Folder>,
    files: Vec<File>,
}

fn ctx_of<'a>(ctx: &'a Context<'_>) -> GqlResult<&'a TokenCtx> {
    ctx.data::<TokenCtx>()
        .map_err(|_| async_graphql::Error::new("unauthorized: missing or invalid token"))
}

fn parse_id(id: &ID) -> GqlResult<i64> {
    id.parse::<i64>()
        .map_err(|_| async_graphql::Error::new("invalid id"))
}

fn gerr<E: std::fmt::Display>(e: E) -> async_graphql::Error {
    async_graphql::Error::new(e.to_string())
}

fn require_admin_gql(tok: &TokenCtx) -> GqlResult<()> {
    if tok.is_admin {
        Ok(())
    } else {
        Err(async_graphql::Error::new("admin token required"))
    }
}

fn valid_permission_str(p: &str) -> bool {
    matches!(p, "read" | "write" | "comment")
}

// ---------- admin: tokens ----------

#[derive(SimpleObject)]
pub struct Token {
    id: ID,
    token: Option<String>,
    owner: String,
    is_admin: bool,
    quota_bytes: i64,
    used_bytes: i64,
    expires_at: Option<String>,
}

struct TokenRow {
    id: i64,
    token: String,
    owner: String,
    is_admin: bool,
    quota_bytes: i64,
    used_bytes: i64,
    expires_at: Option<String>,
}
impl From<&mut hiqlite::Row<'_>> for TokenRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            token: row.get("token"),
            owner: row.get("owner"),
            is_admin: row.get::<i64>("is_admin") != 0,
            quota_bytes: row.get("quota_bytes"),
            used_bytes: row.get("used_bytes"),
            expires_at: row.get("expires_at"),
        }
    }
}
impl From<TokenRow> for Token {
    fn from(r: TokenRow) -> Self {
        Token {
            id: ID(r.id.to_string()),
            token: Some(r.token),
            owner: r.owner,
            is_admin: r.is_admin,
            quota_bytes: r.quota_bytes,
            used_bytes: r.used_bytes,
            expires_at: r.expires_at,
        }
    }
}

// ---------- audit ----------

#[derive(SimpleObject)]
pub struct AdminAuditEntry {
    id: ID,
    actor_owner: String,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<ID>,
    detail: Option<String>,
    created_at: String,
}
struct AdminAuditRow {
    id: i64,
    actor_owner: String,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    detail: Option<String>,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for AdminAuditRow {
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
impl From<AdminAuditRow> for AdminAuditEntry {
    fn from(r: AdminAuditRow) -> Self {
        AdminAuditEntry {
            id: ID(r.id.to_string()),
            actor_owner: r.actor_owner,
            action: r.action,
            resource_type: r.resource_type,
            resource_id: r.resource_id.map(|i| ID(i.to_string())),
            detail: r.detail,
            created_at: r.created_at,
        }
    }
}

#[derive(SimpleObject)]
pub struct MyAuditEntry {
    id: ID,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<ID>,
    detail: Option<String>,
    created_at: String,
}
struct MyAuditRow {
    id: i64,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    detail: Option<String>,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for MyAuditRow {
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
impl From<MyAuditRow> for MyAuditEntry {
    fn from(r: MyAuditRow) -> Self {
        MyAuditEntry {
            id: ID(r.id.to_string()),
            action: r.action,
            resource_type: r.resource_type,
            resource_id: r.resource_id.map(|i| ID(i.to_string())),
            detail: r.detail,
            created_at: r.created_at,
        }
    }
}

fn clamp_audit_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(100).clamp(1, 1000)
}

// ---------- tags / favorites ----------

#[derive(SimpleObject)]
pub struct Tag {
    id: ID,
    name: String,
}
struct TagRow {
    id: i64,
    name: String,
}
impl From<&mut hiqlite::Row<'_>> for TagRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id"), name: row.get("name") }
    }
}
impl From<TagRow> for Tag {
    fn from(r: TagRow) -> Self {
        Tag { id: ID(r.id.to_string()), name: r.name }
    }
}

struct TagOwnerRow {
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for TagOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { owner_token_id: row.get("owner_token_id") }
    }
}

#[derive(SimpleObject)]
pub struct ResourceTag {
    id: ID,
    resource_type: String,
    resource_id: ID,
    tag_id: ID,
}

#[derive(SimpleObject)]
pub struct ResourceTagEntry {
    id: ID,
    tag_id: ID,
    name: String,
}
struct ResourceTagEntryRow {
    id: i64,
    tag_id: i64,
    name: String,
}
impl From<&mut hiqlite::Row<'_>> for ResourceTagEntryRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id"), tag_id: row.get("tag_id"), name: row.get("name") }
    }
}
impl From<ResourceTagEntryRow> for ResourceTagEntry {
    fn from(r: ResourceTagEntryRow) -> Self {
        ResourceTagEntry { id: ID(r.id.to_string()), tag_id: ID(r.tag_id.to_string()), name: r.name }
    }
}

struct ResourceTagOwnerRow {
    tag_owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for ResourceTagOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { tag_owner_token_id: row.get("tag_owner_token_id") }
    }
}

#[derive(SimpleObject)]
pub struct Favorite {
    id: ID,
    resource_type: String,
    resource_id: ID,
    name: Option<String>,
}
struct FavoriteRow {
    id: i64,
    resource_type: String,
    resource_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for FavoriteRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            resource_type: row.get("resource_type"),
            resource_id: row.get("resource_id"),
        }
    }
}

struct FavoriteOwnerRow {
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for FavoriteOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { owner_token_id: row.get("owner_token_id") }
    }
}

/// Mirrors tags.rs/comments.rs's `resource_exists`: only files/folders, non-deleted.
async fn gql_resource_exists(state: &AppState, resource_type: &str, resource_id: i64) -> GqlResult<bool> {
    let table = match resource_type {
        "file" | "files" => "files",
        "folder" | "folders" => "folders",
        _ => return Ok(false),
    };
    let sql = format!("SELECT id FROM {table} WHERE id = $1 AND deleted_at IS NULL");
    let row: Option<IdRow> = state.db.query_map_optional(sql, params!(resource_id)).await.map_err(gerr)?;
    Ok(row.is_some())
}

async fn gql_resource_name(state: &AppState, resource_type: &str, resource_id: i64) -> Option<String> {
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
    let fetched: Option<NameRow> = state.db.query_map_optional(sql, params!(resource_id)).await.ok().flatten();
    fetched.map(|r| r.name)
}

// ---------- sharing ----------

#[derive(SimpleObject)]
pub struct Share {
    id: ID,
    share_token: String,
    resource_type: String,
    resource_id: ID,
    permission: String,
    expires_at: Option<String>,
    created_at: String,
}
struct ShareRow {
    id: i64,
    resource_type: String,
    resource_id: i64,
    owner_token_id: i64,
    share_token: String,
    #[allow(dead_code)]
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
impl From<ShareRow> for Share {
    fn from(r: ShareRow) -> Self {
        Share {
            id: ID(r.id.to_string()),
            share_token: r.share_token,
            resource_type: r.resource_type,
            resource_id: ID(r.resource_id.to_string()),
            permission: r.permission,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }
    }
}

#[derive(SimpleObject)]
pub struct CreateShareResult {
    id: ID,
    share_token: String,
    permission: String,
    expires_at: Option<String>,
}

#[derive(SimpleObject)]
pub struct Permission {
    id: ID,
    resource_type: String,
    resource_id: ID,
    grantee_token_id: Option<ID>,
    grantee_group_id: Option<ID>,
    permission: String,
    granted_by_token_id: ID,
    created_at: String,
}
struct PermissionRow {
    id: i64,
    resource_type: String,
    resource_id: i64,
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
impl From<PermissionRow> for Permission {
    fn from(r: PermissionRow) -> Self {
        Permission {
            id: ID(r.id.to_string()),
            resource_type: r.resource_type,
            resource_id: ID(r.resource_id.to_string()),
            grantee_token_id: if r.grantee_token_id == 0 { None } else { Some(ID(r.grantee_token_id.to_string())) },
            grantee_group_id: r.grantee_group_id.map(|i| ID(i.to_string())),
            permission: r.permission,
            granted_by_token_id: ID(r.granted_by_token_id.to_string()),
            created_at: r.created_at,
        }
    }
}

/// Mirrors sharing.rs's `resource_owner`: 'file'/'folder' only, non-deleted, or error.
async fn gql_resource_owner(state: &AppState, resource_type: &str, resource_id: i64) -> GqlResult<i64> {
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
        _ => return Err(async_graphql::Error::new("resource_type must be 'file' or 'folder'")),
    }
    .map_err(gerr)?;
    owner.map(|r| r.id).ok_or(async_graphql::Error::new("resource not found"))
}

fn gql_check_owner_or_admin(ctx: &TokenCtx, owner_token_id: i64) -> GqlResult<()> {
    if ctx.is_admin || ctx.id == owner_token_id {
        Ok(())
    } else {
        Err(async_graphql::Error::new("not owner"))
    }
}

// ---------- comments ----------

fn extract_mentions_gql(body: &str) -> Vec<String> {
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

#[derive(SimpleObject)]
pub struct Comment {
    id: ID,
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

#[derive(SimpleObject)]
pub struct CommentCreated {
    id: ID,
    body: String,
    mentions: Vec<String>,
    created_at: String,
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

// ---------- groups ----------

#[derive(SimpleObject)]
pub struct Group {
    id: ID,
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
        Self { id: row.get("id"), name: row.get("name"), created_at: row.get("created_at") }
    }
}
impl From<GroupRow> for Group {
    fn from(r: GroupRow) -> Self {
        Group { id: ID(r.id.to_string()), name: r.name, created_at: r.created_at }
    }
}

#[derive(SimpleObject)]
pub struct GroupMember {
    token_id: ID,
    owner: String,
}
struct GroupMemberRow {
    token_id: i64,
    owner: String,
}
impl From<&mut hiqlite::Row<'_>> for GroupMemberRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { token_id: row.get("token_id"), owner: row.get("owner") }
    }
}
impl From<GroupMemberRow> for GroupMember {
    fn from(r: GroupMemberRow) -> Self {
        GroupMember { token_id: ID(r.token_id.to_string()), owner: r.owner }
    }
}

// ---------- trash ----------

#[derive(SimpleObject)]
pub struct TrashEntry {
    id: ID,
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
        Self { id: row.get("id"), name: row.get("name"), deleted_at: row.get("deleted_at") }
    }
}
impl From<TrashRow> for TrashEntry {
    fn from(r: TrashRow) -> Self {
        TrashEntry { id: ID(r.id.to_string()), name: r.name, deleted_at: r.deleted_at }
    }
}

#[derive(SimpleObject)]
pub struct TrashList {
    folders: Vec<TrashEntry>,
    files: Vec<TrashEntry>,
}

fn gql_table_for(kind: &str) -> GqlResult<&'static str> {
    match kind {
        "file" => Ok("files"),
        "folder" => Ok("folders"),
        _ => Err(async_graphql::Error::new("resourceType must be 'file' or 'folder'")),
    }
}

async fn gql_check_owned_deleted(state: &AppState, table: &str, id: i64, owner: Option<i64>) -> GqlResult<bool> {
    let row: Option<IdRow> = if let Some(owner_id) = owner {
        let sql = format!("SELECT id FROM {table} WHERE id = $1 AND owner_token_id = $2 AND deleted_at IS NOT NULL");
        state.db.query_map_optional(sql, params!(id, owner_id)).await
    } else {
        let sql = format!("SELECT id FROM {table} WHERE id = $1 AND deleted_at IS NOT NULL");
        state.db.query_map_optional(sql, params!(id)).await
    }
    .map_err(gerr)?;
    Ok(row.is_some())
}

// ---------- retention ----------

const DEFAULT_RETENTION_DAYS: i64 = 30;

#[derive(SimpleObject)]
pub struct RetentionPolicy {
    trash_retention_days: i64,
}

struct DaysRow {
    trash_retention_days: i64,
}
impl From<&mut hiqlite::Row<'_>> for DaysRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { trash_retention_days: row.get("trash_retention_days") }
    }
}

async fn gql_global_default_days(db: &hiqlite::Client) -> i64 {
    let row: Option<DaysRow> = db
        .query_map_optional(
            "SELECT trash_retention_days FROM retention_policy WHERE owner_token_id IS NULL",
            params!(),
        )
        .await
        .unwrap_or(None);
    row.map(|r| r.trash_retention_days).unwrap_or(DEFAULT_RETENTION_DAYS)
}

async fn gql_user_override_days(db: &hiqlite::Client, owner_token_id: i64) -> Option<i64> {
    let row: Option<DaysRow> = db
        .query_map_optional(
            "SELECT trash_retention_days FROM retention_policy WHERE owner_token_id = $1",
            params!(owner_token_id),
        )
        .await
        .unwrap_or(None);
    row.map(|r| r.trash_retention_days)
}

async fn gql_upsert_policy(db: &hiqlite::Client, owner_token_id: Option<i64>, days: i64) -> GqlResult<()> {
    let created_at = chrono::Utc::now().to_rfc3339();
    let sql = if owner_token_id.is_some() {
        "INSERT INTO retention_policy (owner_token_id, trash_retention_days, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT(owner_token_id) DO UPDATE SET trash_retention_days = excluded.trash_retention_days"
    } else {
        "INSERT INTO retention_policy (owner_token_id, trash_retention_days, created_at) VALUES (NULL, $2, $3) \
         ON CONFLICT(owner_token_id) DO UPDATE SET trash_retention_days = excluded.trash_retention_days"
    };
    db.execute(sql, params!(owner_token_id, days, created_at)).await.map_err(gerr)?;
    Ok(())
}

// ---------- storage backends ----------

#[derive(SimpleObject)]
pub struct StorageBackend {
    id: ID,
    name: String,
    kind: String,
    /// JSON-encoded config, secrets redacted (mirrors REST's storage_backends.rs redaction —
    /// s3 access_key/secret_key never come back out over the API once stored).
    config: String,
    is_active: bool,
    created_at: String,
}

struct StorageBackendRow {
    id: i64,
    name: String,
    kind: String,
    config: String,
    is_active: bool,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for StorageBackendRow {
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

/// Mirrors storage_backends.rs's `redact_config`: strips s3 access_key/secret_key before the
/// config ever goes back out over the API.
fn gql_redact_config(kind: &str, config: &str) -> String {
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
    v.to_string()
}

impl From<StorageBackendRow> for StorageBackend {
    fn from(r: StorageBackendRow) -> Self {
        StorageBackend {
            id: ID(r.id.to_string()),
            name: r.name,
            config: gql_redact_config(&r.kind, &r.config),
            kind: r.kind,
            is_active: r.is_active,
            created_at: r.created_at,
        }
    }
}

/// Mirrors storage_backends.rs's `validate_config`.
fn gql_validate_backend_config(kind: &str, config: &serde_json::Value) -> GqlResult<()> {
    let has_str = |k: &str| config.get(k).and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty());
    match kind {
        "fs" => {
            if has_str("path") {
                Ok(())
            } else {
                Err(async_graphql::Error::new(
                    "fs config requires non-empty 'path' (for CIFS/NFS this is the local OS mount point of the share)",
                ))
            }
        }
        "s3" => {
            if has_str("bucket") && has_str("region") && has_str("access_key") && has_str("secret_key") {
                Ok(())
            } else {
                Err(async_graphql::Error::new("s3 config requires 'bucket', 'region', 'access_key', 'secret_key' ('endpoint' optional)"))
            }
        }
        _ => Err(async_graphql::Error::new("kind must be 'fs' or 's3'")),
    }
}

pub struct Query;

#[Object]
impl Query {
    async fn folder(&self, gctx: &Context<'_>, id: ID) -> GqlResult<Option<Folder>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let fid = parse_id(&id)?;
        let row: Option<FolderRow> = state
            .db
            .query_map_optional(
                "SELECT id, name, parent_id, created_at, owner_token_id FROM folders WHERE id = $1 AND deleted_at IS NULL",
                params!(fid),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(row
            .filter(|r| r.owner_token_id == tok.id || tok.is_admin)
            .map(Into::into))
    }

    async fn folders(&self, gctx: &Context<'_>, parent_id: Option<ID>) -> GqlResult<Vec<Folder>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rows: Vec<FolderRow> = match parent_id {
            Some(pid) => {
                let pid = parse_id(&pid)?;
                state
                    .db
                    .query_map(
                        "SELECT id, name, parent_id, created_at, owner_token_id FROM folders \
                         WHERE parent_id = $1 AND deleted_at IS NULL AND (owner_token_id = $2 OR $3)",
                        params!(pid, tok.id, tok.is_admin as i64),
                    )
                    .await
            }
            None => {
                state
                    .db
                    .query_map(
                        "SELECT id, name, parent_id, created_at, owner_token_id FROM folders \
                         WHERE parent_id IS NULL AND deleted_at IS NULL AND (owner_token_id = $1 OR $2)",
                        params!(tok.id, tok.is_admin as i64),
                    )
                    .await
            }
        }
        .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn file(&self, gctx: &Context<'_>, id: ID) -> GqlResult<Option<File>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let fid = parse_id(&id)?;
        let row: Option<FileRow> = state
            .db
            .query_map_optional(
                "SELECT f.id AS id, f.name AS name, f.folder_id AS folder_id, \
                 COALESCE(v.size, 0) AS size, f.created_at AS created_at, \
                 v.version_no AS current_version_no, f.owner_token_id AS owner_token_id \
                 FROM files f LEFT JOIN file_versions v ON v.id = f.current_version_id \
                 WHERE f.id = $1 AND f.deleted_at IS NULL",
                params!(fid),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(row
            .filter(|r| r.owner_token_id == tok.id || tok.is_admin)
            .map(Into::into))
    }

    async fn file_versions(&self, gctx: &Context<'_>, file_id: ID) -> GqlResult<Vec<FileVersion>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let fid = parse_id(&file_id)?;
        // Ensure caller owns (or is admin for) the parent file before listing versions.
        let owner: Option<(i64,)> = state
            .db
            .query_map_optional(
                "SELECT owner_token_id FROM files WHERE id = $1 AND deleted_at IS NULL",
                params!(fid),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?
            .map(|r: IdOwnerRow| (r.owner_token_id,));
        let Some((owner_id,)) = owner else {
            return Ok(vec![]);
        };
        if owner_id != tok.id && !tok.is_admin {
            return Ok(vec![]);
        }
        let rows: Vec<FileVersionRow> = state
            .db
            .query_map(
                "SELECT id, version_no, size, created_at FROM file_versions WHERE file_id = $1 ORDER BY version_no",
                params!(fid),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn search(&self, gctx: &Context<'_>, q: String) -> GqlResult<SearchResult> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let term = q.trim();
        if term.is_empty() {
            return Err(async_graphql::Error::new("missing q"));
        }
        let folders: Vec<FolderRow> = state
            .db
            .query_map(
                "SELECT id, name, parent_id, created_at, owner_token_id FROM folders \
                 WHERE deleted_at IS NULL AND (owner_token_id = $1 OR $2) \
                 AND name LIKE '%' || $3 || '%' COLLATE NOCASE LIMIT 100",
                params!(tok.id, tok.is_admin as i64, term),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        let files: Vec<FileRow> = state
            .db
            .query_map(
                "SELECT f.id AS id, f.name AS name, f.folder_id AS folder_id, \
                 COALESCE(v.size, 0) AS size, f.created_at AS created_at, \
                 v.version_no AS current_version_no, f.owner_token_id AS owner_token_id \
                 FROM files f LEFT JOIN file_versions v ON v.id = f.current_version_id \
                 WHERE f.deleted_at IS NULL AND (f.owner_token_id = $1 OR $2) \
                 AND f.name LIKE '%' || $3 || '%' COLLATE NOCASE LIMIT 100",
                params!(tok.id, tok.is_admin as i64, term),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(SearchResult {
            folders: folders.into_iter().map(Into::into).collect(),
            files: files.into_iter().map(Into::into).collect(),
        })
    }

    /// Mirrors GET /admin/tokens (admin.rs::list_tokens).
    async fn tokens(&self, gctx: &Context<'_>) -> GqlResult<Vec<Token>> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let rows: Vec<TokenRow> = state
            .db
            .query_map(
                "SELECT id, token, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens",
                params!(),
            )
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /admin/audit-log (audit.rs::admin_list).
    async fn audit_log(
        &self,
        gctx: &Context<'_>,
        limit: Option<i64>,
        resource_type: Option<String>,
        resource_id: Option<ID>,
        actor_token_id: Option<ID>,
    ) -> GqlResult<Vec<AdminAuditEntry>> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let limit = clamp_audit_limit(limit);
        let resource_id = resource_id.as_ref().map(parse_id).transpose()?;
        let actor_token_id = actor_token_id.as_ref().map(parse_id).transpose()?;
        let rows: Vec<AdminAuditRow> = state
            .db
            .query_map(
                "SELECT a.id, t.owner AS actor_owner, a.action, a.resource_type, a.resource_id, a.detail, a.created_at \
                 FROM audit_log a JOIN tokens t ON t.id = a.actor_token_id \
                 WHERE ($1 IS NULL OR a.resource_type = $1) \
                   AND ($2 IS NULL OR a.resource_id = $2) \
                   AND ($3 IS NULL OR a.actor_token_id = $3) \
                 ORDER BY a.created_at DESC LIMIT $4",
                params!(resource_type, resource_id, actor_token_id, limit),
            )
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /audit-log/mine (audit.rs::mine_list).
    async fn my_audit_log(&self, gctx: &Context<'_>, limit: Option<i64>) -> GqlResult<Vec<MyAuditEntry>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let limit = clamp_audit_limit(limit);
        let rows: Vec<MyAuditRow> = state
            .db
            .query_map(
                "SELECT id, action, resource_type, resource_id, detail, created_at \
                 FROM audit_log WHERE actor_token_id = $1 ORDER BY created_at DESC LIMIT $2",
                params!(tok.id, limit),
            )
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /tags (tags.rs::list_tags).
    async fn tags(&self, gctx: &Context<'_>) -> GqlResult<Vec<Tag>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rows: Vec<TagRow> = state
            .db
            .query_map("SELECT id, name FROM tags WHERE owner_token_id = $1", params!(tok.id))
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /resource-tags (tags.rs::list_resource_tags).
    async fn resource_tags(
        &self,
        gctx: &Context<'_>,
        resource_type: String,
        resource_id: ID,
    ) -> GqlResult<Vec<ResourceTagEntry>> {
        let _tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        let rows: Vec<ResourceTagEntryRow> = state
            .db
            .query_map(
                "SELECT rt.id AS id, rt.tag_id AS tag_id, t.name AS name \
                 FROM resource_tags rt JOIN tags t ON t.id = rt.tag_id \
                 WHERE rt.resource_type = $1 AND rt.resource_id = $2",
                params!(&resource_type, rid),
            )
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /favorites (tags.rs::list_favorites).
    async fn favorites(&self, gctx: &Context<'_>) -> GqlResult<Vec<Favorite>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rows: Vec<FavoriteRow> = state
            .db
            .query_map(
                "SELECT id, resource_type, resource_id FROM favorites WHERE owner_token_id = $1",
                params!(tok.id),
            )
            .await
            .map_err(gerr)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let name = gql_resource_name(state, &r.resource_type, r.resource_id).await;
            out.push(Favorite {
                id: ID(r.id.to_string()),
                resource_type: r.resource_type,
                resource_id: ID(r.resource_id.to_string()),
                name,
            });
        }
        Ok(out)
    }

    /// Mirrors GET /shares (sharing.rs::list_shares).
    async fn shares(&self, gctx: &Context<'_>) -> GqlResult<Vec<Share>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rows: Vec<ShareRow> = state
            .db
            .query_map(
                "SELECT id, resource_type, resource_id, owner_token_id, share_token, password_hash, expires_at, permission, created_at \
                 FROM shares WHERE owner_token_id = $1",
                params!(tok.id),
            )
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /permissions (sharing.rs::list_permissions).
    async fn permissions(&self, gctx: &Context<'_>, resource_type: String, resource_id: ID) -> GqlResult<Vec<Permission>> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        let owner_token_id = gql_resource_owner(state, &resource_type, rid).await?;
        gql_check_owner_or_admin(tok, owner_token_id)?;
        let rows: Vec<PermissionRow> = state
            .db
            .query_map(
                "SELECT id, resource_type, resource_id, grantee_token_id, grantee_group_id, permission, granted_by_token_id, created_at \
                 FROM permissions WHERE resource_type = $1 AND resource_id = $2",
                params!(&resource_type, rid),
            )
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /comments (comments.rs::list_comments).
    async fn comments(&self, gctx: &Context<'_>, resource_type: String, resource_id: ID) -> GqlResult<Vec<Comment>> {
        let _tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        let rows: Vec<CommentListRow> = state
            .db
            .query_map(
                "SELECT c.id AS id, t.owner AS author_owner, c.body AS body, c.mentions AS mentions, c.created_at AS created_at \
                 FROM comments c JOIN tokens t ON t.id = c.author_token_id \
                 WHERE c.resource_type = $1 AND c.resource_id = $2 AND c.deleted_at IS NULL \
                 ORDER BY c.created_at",
                params!(&resource_type, rid),
            )
            .await
            .map_err(gerr)?;
        Ok(rows
            .into_iter()
            .map(|r| Comment {
                id: ID(r.id.to_string()),
                author_owner: r.author_owner,
                body: r.body,
                mentions: serde_json::from_str(&r.mentions).unwrap_or_default(),
                created_at: r.created_at,
            })
            .collect())
    }

    /// Mirrors GET /admin/groups (groups.rs::list_groups).
    async fn groups(&self, gctx: &Context<'_>) -> GqlResult<Vec<Group>> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let rows: Vec<GroupRow> = state
            .db
            .query_map("SELECT id, name, created_at FROM groups", params!())
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /admin/groups/{id}/members (groups.rs::list_members).
    async fn group_members(&self, gctx: &Context<'_>, group_id: ID) -> GqlResult<Vec<GroupMember>> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let gid = parse_id(&group_id)?;
        let rows: Vec<GroupMemberRow> = state
            .db
            .query_map(
                "SELECT gm.token_id AS token_id, t.owner AS owner FROM group_members gm \
                 JOIN tokens t ON t.id = gm.token_id WHERE gm.group_id = $1",
                params!(gid),
            )
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mirrors GET /trash (trash.rs::list_trash), scoped to the caller's own trash.
    async fn trash(&self, gctx: &Context<'_>) -> GqlResult<TrashList> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let folders: Vec<TrashRow> = state
            .db
            .query_map(
                "SELECT id, name, deleted_at FROM folders WHERE deleted_at IS NOT NULL AND owner_token_id = $1",
                params!(tok.id),
            )
            .await
            .map_err(gerr)?;
        let files: Vec<TrashRow> = state
            .db
            .query_map(
                "SELECT id, name, deleted_at FROM files WHERE deleted_at IS NOT NULL AND owner_token_id = $1",
                params!(tok.id),
            )
            .await
            .map_err(gerr)?;
        Ok(TrashList {
            folders: folders.into_iter().map(Into::into).collect(),
            files: files.into_iter().map(Into::into).collect(),
        })
    }

    /// Mirrors GET /retention-policy/mine (retention.rs::get_my_policy).
    async fn my_retention_policy(&self, gctx: &Context<'_>) -> GqlResult<RetentionPolicy> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let days = match gql_user_override_days(&state.db, tok.id).await {
            Some(d) => d,
            None => gql_global_default_days(&state.db).await,
        };
        Ok(RetentionPolicy { trash_retention_days: days })
    }

    /// Mirrors GET /admin/retention-policy (retention.rs::get_global_policy).
    async fn global_retention_policy(&self, gctx: &Context<'_>) -> GqlResult<RetentionPolicy> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        Ok(RetentionPolicy { trash_retention_days: gql_global_default_days(&state.db).await })
    }

    /// Mirrors GET /admin/storage-backends (storage_backends.rs::list_backends).
    async fn storage_backends(&self, gctx: &Context<'_>) -> GqlResult<Vec<StorageBackend>> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let rows: Vec<StorageBackendRow> = state
            .db
            .query_map("SELECT id, name, kind, config, is_active, created_at FROM storage_backends", params!())
            .await
            .map_err(gerr)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

// ponytail: tiny helper row just for the owner_token_id column reused by file_versions().
struct IdOwnerRow {
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for IdOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { owner_token_id: row.get("owner_token_id") }
    }
}

pub struct Mutation;

#[Object]
impl Mutation {
    async fn create_folder(
        &self,
        gctx: &Context<'_>,
        name: String,
        parent_id: Option<ID>,
    ) -> GqlResult<Folder> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let pid = parent_id.as_ref().map(parse_id).transpose()?;
        if let Some(pid) = pid {
            let owner: Option<IdOwnerRow> = state
                .db
                .query_map_optional(
                    "SELECT owner_token_id FROM folders WHERE id = $1 AND deleted_at IS NULL",
                    params!(pid),
                )
                .await
                .map_err(|e| async_graphql::Error::new(e.to_string()))?;
            match owner {
                Some(o) if o.owner_token_id == tok.id || tok.is_admin => {}
                Some(_) => return Err(async_graphql::Error::new("not owner")),
                None => return Err(async_graphql::Error::new("parent folder not found")),
            }
        }
        let created_at = chrono::Utc::now().to_rfc3339();
        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO folders (parent_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(pid, &name, tok.id, &created_at),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(Folder {
            id: ID(id_row.id.to_string()),
            name,
            parent_id: pid.map(|p| ID(p.to_string())),
            created_at,
        })
    }

    async fn delete_folder(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let fid = parse_id(&id)?;
        let owner: Option<IdOwnerRow> = state
            .db
            .query_map_optional(
                "SELECT owner_token_id FROM folders WHERE id = $1 AND deleted_at IS NULL",
                params!(fid),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        match owner {
            None => return Ok(false),
            Some(o) if o.owner_token_id != tok.id && !tok.is_admin => {
                return Err(async_graphql::Error::new("not owner"))
            }
            _ => {}
        }
        let deleted_at = chrono::Utc::now().to_rfc3339();
        state
            .db
            .execute(
                "UPDATE folders SET deleted_at = $1 WHERE id = $2",
                params!(&deleted_at, fid),
            )
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(true)
    }

    /// Mirrors POST /admin/tokens (admin.rs::create_token).
    async fn create_token(
        &self,
        gctx: &Context<'_>,
        owner: String,
        #[graphql(default)] is_admin: bool,
        #[graphql(default_with = "10_737_418_240i64")] quota_bytes: i64,
        #[graphql(default = 30)] duration_days: i64,
    ) -> GqlResult<Token> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let token = format!("plaste-{}", uuid::Uuid::new_v4());
        let created_at = chrono::Utc::now();
        let expires_at = (created_at + chrono::Duration::days(duration_days)).to_rfc3339();
        let created_at = created_at.to_rfc3339();

        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO tokens (token, owner, is_admin, quota_bytes, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                params!(&token, &owner, is_admin, quota_bytes, created_at, &expires_at),
            )
            .await
            .map_err(gerr)?;

        crate::audit::log(&state.db, tok.id, "token.create", Some("token"), Some(id_row.id), None).await;

        Ok(Token {
            id: ID(id_row.id.to_string()),
            token: Some(token),
            owner,
            is_admin,
            quota_bytes,
            used_bytes: 0,
            expires_at: Some(expires_at),
        })
    }

    /// Mirrors DELETE /admin/tokens/{id} (admin.rs::delete_token).
    async fn delete_token(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let tid = parse_id(&id)?;
        state.db.execute("DELETE FROM tokens WHERE id = $1", params!(tid)).await.map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "token.delete", Some("token"), Some(tid), None).await;
        Ok(true)
    }

    /// Mirrors PUT /admin/tokens/{id}/renew (admin.rs::renew_token).
    async fn renew_token(&self, gctx: &Context<'_>, id: ID, duration_days: i64) -> GqlResult<Token> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let tid = parse_id(&id)?;
        let expires_at = (chrono::Utc::now() + chrono::Duration::days(duration_days)).to_rfc3339();
        state
            .db
            .execute("UPDATE tokens SET expires_at = $1 WHERE id = $2", params!(&expires_at, tid))
            .await
            .map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "token.renew", Some("token"), Some(tid), None).await;

        let row: Option<TokenRow> = state
            .db
            .query_map_optional(
                "SELECT id, token, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens WHERE id = $1",
                params!(tid),
            )
            .await
            .map_err(gerr)?;
        // ponytail: token string omitted here (renew never returns the secret over REST either).
        let mut t: Token = row.ok_or(async_graphql::Error::new("token not found"))?.into();
        t.token = None;
        Ok(t)
    }

    /// Mirrors POST /tags (tags.rs::create_tag).
    async fn create_tag(&self, gctx: &Context<'_>, name: String) -> GqlResult<Tag> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let created_at = chrono::Utc::now().to_rfc3339();
        let inserted: Result<IdRow, _> = state
            .db
            .execute_returning_map_one(
                "INSERT INTO tags (owner_token_id, name, created_at) VALUES ($1, $2, $3) RETURNING id",
                params!(tok.id, &name, created_at),
            )
            .await;
        let id = match inserted {
            Ok(row) => row.id,
            Err(_) => {
                let existing: Option<IdRow> = state
                    .db
                    .query_map_optional("SELECT id FROM tags WHERE owner_token_id = $1 AND name = $2", params!(tok.id, &name))
                    .await
                    .map_err(gerr)?;
                existing.ok_or(async_graphql::Error::new("db error"))?.id
            }
        };
        Ok(Tag { id: ID(id.to_string()), name })
    }

    /// Mirrors DELETE /tags/{id} (tags.rs::delete_tag).
    async fn delete_tag(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let tid = parse_id(&id)?;
        let row: Option<TagOwnerRow> = state
            .db
            .query_map_optional("SELECT owner_token_id FROM tags WHERE id = $1", params!(tid))
            .await
            .map_err(gerr)?;
        let row = row.ok_or(async_graphql::Error::new("tag not found"))?;
        if row.owner_token_id != tok.id {
            return Err(async_graphql::Error::new("not owner"));
        }
        state.db.execute("DELETE FROM resource_tags WHERE tag_id = $1", params!(tid)).await.map_err(gerr)?;
        state.db.execute("DELETE FROM tags WHERE id = $1", params!(tid)).await.map_err(gerr)?;
        Ok(true)
    }

    /// Mirrors POST /resource-tags (tags.rs::attach_tag).
    async fn attach_tag(&self, gctx: &Context<'_>, resource_type: String, resource_id: ID, tag_id: ID) -> GqlResult<ResourceTag> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        let tag_id_i = parse_id(&tag_id)?;
        let tag: Option<TagOwnerRow> = state
            .db
            .query_map_optional("SELECT owner_token_id FROM tags WHERE id = $1", params!(tag_id_i))
            .await
            .map_err(gerr)?;
        let tag = tag.ok_or(async_graphql::Error::new("tag not found"))?;
        if tag.owner_token_id != tok.id {
            return Err(async_graphql::Error::new("not owner"));
        }
        if !gql_resource_exists(state, &resource_type, rid).await? {
            return Err(async_graphql::Error::new("resource not found"));
        }
        let created_at = chrono::Utc::now().to_rfc3339();
        let inserted: Result<IdRow, _> = state
            .db
            .execute_returning_map_one(
                "INSERT INTO resource_tags (resource_type, resource_id, tag_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(&resource_type, rid, tag_id_i, created_at),
            )
            .await;
        let id = match inserted {
            Ok(row) => row.id,
            Err(_) => {
                let existing: Option<IdRow> = state
                    .db
                    .query_map_optional(
                        "SELECT id FROM resource_tags WHERE resource_type = $1 AND resource_id = $2 AND tag_id = $3",
                        params!(&resource_type, rid, tag_id_i),
                    )
                    .await
                    .map_err(gerr)?;
                existing.ok_or(async_graphql::Error::new("db error"))?.id
            }
        };
        Ok(ResourceTag { id: ID(id.to_string()), resource_type, resource_id: ID(rid.to_string()), tag_id: ID(tag_id_i.to_string()) })
    }

    /// Mirrors DELETE /resource-tags/{id} (tags.rs::detach_tag).
    async fn detach_tag(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rtid = parse_id(&id)?;
        let row: Option<ResourceTagOwnerRow> = state
            .db
            .query_map_optional(
                "SELECT t.owner_token_id AS tag_owner_token_id FROM resource_tags rt JOIN tags t ON t.id = rt.tag_id WHERE rt.id = $1",
                params!(rtid),
            )
            .await
            .map_err(gerr)?;
        let row = row.ok_or(async_graphql::Error::new("resource tag not found"))?;
        if row.tag_owner_token_id != tok.id {
            return Err(async_graphql::Error::new("not owner"));
        }
        state.db.execute("DELETE FROM resource_tags WHERE id = $1", params!(rtid)).await.map_err(gerr)?;
        Ok(true)
    }

    /// Mirrors POST /favorites (tags.rs::add_favorite).
    async fn add_favorite(&self, gctx: &Context<'_>, resource_type: String, resource_id: ID) -> GqlResult<Favorite> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        if !gql_resource_exists(state, &resource_type, rid).await? {
            return Err(async_graphql::Error::new("resource not found"));
        }
        let created_at = chrono::Utc::now().to_rfc3339();
        let inserted: Result<IdRow, _> = state
            .db
            .execute_returning_map_one(
                "INSERT INTO favorites (owner_token_id, resource_type, resource_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(tok.id, &resource_type, rid, created_at),
            )
            .await;
        let id = match inserted {
            Ok(row) => row.id,
            Err(_) => {
                let existing: Option<IdRow> = state
                    .db
                    .query_map_optional(
                        "SELECT id FROM favorites WHERE owner_token_id = $1 AND resource_type = $2 AND resource_id = $3",
                        params!(tok.id, &resource_type, rid),
                    )
                    .await
                    .map_err(gerr)?;
                existing.ok_or(async_graphql::Error::new("db error"))?.id
            }
        };
        Ok(Favorite { id: ID(id.to_string()), resource_type, resource_id: ID(rid.to_string()), name: None })
    }

    /// Mirrors DELETE /favorites/{id} (tags.rs::remove_favorite).
    async fn remove_favorite(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let fid = parse_id(&id)?;
        let row: Option<FavoriteOwnerRow> = state
            .db
            .query_map_optional("SELECT owner_token_id FROM favorites WHERE id = $1", params!(fid))
            .await
            .map_err(gerr)?;
        let row = row.ok_or(async_graphql::Error::new("favorite not found"))?;
        if row.owner_token_id != tok.id {
            return Err(async_graphql::Error::new("not owner"));
        }
        state.db.execute("DELETE FROM favorites WHERE id = $1", params!(fid)).await.map_err(gerr)?;
        Ok(true)
    }

    /// Mirrors POST /shares (sharing.rs::create_share).
    async fn create_share(
        &self,
        gctx: &Context<'_>,
        resource_type: String,
        resource_id: ID,
        password: Option<String>,
        expires_at: Option<String>,
        permission: String,
    ) -> GqlResult<CreateShareResult> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        if !valid_permission_str(&permission) {
            return Err(async_graphql::Error::new("invalid permission"));
        }
        let owner_token_id = gql_resource_owner(state, &resource_type, rid).await?;
        gql_check_owner_or_admin(tok, owner_token_id)?;

        let share_token = uuid::Uuid::new_v4().to_string();
        let password_hash = password.as_deref().map(|p| blake3::hash(p.as_bytes()).to_hex().to_string());
        let created_at = chrono::Utc::now().to_rfc3339();

        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO shares (resource_type, resource_id, owner_token_id, share_token, password_hash, expires_at, permission, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
                params!(&resource_type, rid, tok.id, &share_token, password_hash, &expires_at, &permission, created_at),
            )
            .await
            .map_err(gerr)?;

        crate::audit::log(&state.db, tok.id, "share.create", Some("share"), Some(id_row.id), None).await;

        Ok(CreateShareResult { id: ID(id_row.id.to_string()), share_token, permission, expires_at })
    }

    /// Mirrors DELETE /shares/{id} (sharing.rs::revoke_share).
    async fn revoke_share(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let sid = parse_id(&id)?;
        let share: Option<ShareRow> = state
            .db
            .query_map_optional(
                "SELECT id, resource_type, resource_id, owner_token_id, share_token, password_hash, expires_at, permission, created_at \
                 FROM shares WHERE id = $1",
                params!(sid),
            )
            .await
            .map_err(gerr)?;
        let share = share.ok_or(async_graphql::Error::new("share not found"))?;
        gql_check_owner_or_admin(tok, share.owner_token_id)?;
        state.db.execute("DELETE FROM shares WHERE id = $1", params!(sid)).await.map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "share.revoke", Some("share"), Some(sid), None).await;
        Ok(true)
    }

    /// Mirrors POST /permissions (sharing.rs::create_permission).
    async fn grant_permission(
        &self,
        gctx: &Context<'_>,
        resource_type: String,
        resource_id: ID,
        grantee_owner: Option<String>,
        grantee_group: Option<String>,
        permission: String,
    ) -> GqlResult<Permission> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        if !valid_permission_str(&permission) {
            return Err(async_graphql::Error::new("invalid permission"));
        }
        if grantee_owner.is_some() == grantee_group.is_some() {
            return Err(async_graphql::Error::new("exactly one of granteeOwner/granteeGroup must be provided"));
        }
        let owner_token_id = gql_resource_owner(state, &resource_type, rid).await?;
        gql_check_owner_or_admin(tok, owner_token_id)?;
        let created_at = chrono::Utc::now().to_rfc3339();

        if let Some(grantee_owner) = &grantee_owner {
            let grantee: Option<IdRow> = state
                .db
                .query_map_optional("SELECT id FROM tokens WHERE owner = $1", params!(grantee_owner))
                .await
                .map_err(gerr)?;
            let grantee = grantee.ok_or(async_graphql::Error::new("grantee owner not found"))?;
            let id_row: IdRow = state
                .db
                .execute_returning_map_one(
                    "INSERT INTO permissions (resource_type, resource_id, grantee_token_id, permission, granted_by_token_id, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT(resource_type, resource_id, grantee_token_id) \
                     DO UPDATE SET permission = excluded.permission, granted_by_token_id = excluded.granted_by_token_id \
                     RETURNING id",
                    params!(&resource_type, rid, grantee.id, &permission, tok.id, created_at.clone()),
                )
                .await
                .map_err(gerr)?;
            crate::audit::log(&state.db, tok.id, "permission.grant", Some("permission"), Some(id_row.id), None).await;
            return Ok(Permission {
                id: ID(id_row.id.to_string()),
                resource_type,
                resource_id: ID(rid.to_string()),
                grantee_token_id: Some(ID(grantee.id.to_string())),
                grantee_group_id: None,
                permission,
                granted_by_token_id: ID(tok.id.to_string()),
                created_at,
            });
        }

        let group_name = grantee_group.as_ref().unwrap();
        let group: Option<IdRow> = state
            .db
            .query_map_optional("SELECT id FROM groups WHERE name = $1", params!(group_name))
            .await
            .map_err(gerr)?;
        let group = group.ok_or(async_graphql::Error::new("group not found"))?;
        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO permissions (resource_type, resource_id, grantee_token_id, grantee_group_id, permission, granted_by_token_id, created_at) \
                 VALUES ($1, $2, 0, $3, $4, $5, $6) RETURNING id",
                params!(&resource_type, rid, group.id, &permission, tok.id, created_at.clone()),
            )
            .await
            .map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "permission.grant", Some("permission"), Some(id_row.id), None).await;
        Ok(Permission {
            id: ID(id_row.id.to_string()),
            resource_type,
            resource_id: ID(rid.to_string()),
            grantee_token_id: None,
            grantee_group_id: Some(ID(group.id.to_string())),
            permission,
            granted_by_token_id: ID(tok.id.to_string()),
            created_at,
        })
    }

    /// Mirrors DELETE /permissions/{id} (sharing.rs::revoke_permission).
    async fn revoke_permission(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let pid = parse_id(&id)?;
        let perm: Option<PermissionRow> = state
            .db
            .query_map_optional(
                "SELECT id, resource_type, resource_id, grantee_token_id, grantee_group_id, permission, granted_by_token_id, created_at \
                 FROM permissions WHERE id = $1",
                params!(pid),
            )
            .await
            .map_err(gerr)?;
        let perm = perm.ok_or(async_graphql::Error::new("permission not found"))?;
        let owner_token_id = gql_resource_owner(state, &perm.resource_type, perm.resource_id).await?;
        gql_check_owner_or_admin(tok, owner_token_id)?;
        state.db.execute("DELETE FROM permissions WHERE id = $1", params!(pid)).await.map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "permission.revoke", Some("permission"), Some(pid), None).await;
        Ok(true)
    }

    /// Mirrors POST /comments (comments.rs::create_comment).
    async fn add_comment(&self, gctx: &Context<'_>, resource_type: String, resource_id: ID, body: String) -> GqlResult<CommentCreated> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&resource_id)?;
        if resource_type != "file" && resource_type != "folder" {
            return Err(async_graphql::Error::new("invalid resource_type"));
        }
        if !gql_resource_exists(state, &resource_type, rid).await? {
            return Err(async_graphql::Error::new("resource not found"));
        }
        let mentions = extract_mentions_gql(&body);
        let mentions_json = serde_json::to_string(&mentions).map_err(gerr)?;
        let created_at = chrono::Utc::now().to_rfc3339();
        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO comments (resource_type, resource_id, author_token_id, body, mentions, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                params!(&resource_type, rid, tok.id, &body, mentions_json, created_at.clone()),
            )
            .await
            .map_err(gerr)?;
        Ok(CommentCreated { id: ID(id_row.id.to_string()), body, mentions, created_at })
    }

    /// Mirrors DELETE /comments/{id} (comments.rs::delete_comment).
    async fn delete_comment(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let cid = parse_id(&id)?;
        let row: Option<CommentOwnerRow> = state
            .db
            .query_map_optional("SELECT author_token_id, deleted_at FROM comments WHERE id = $1", params!(cid))
            .await
            .map_err(gerr)?;
        let row = row.ok_or(async_graphql::Error::new("comment not found"))?;
        if row.deleted_at.is_some() {
            return Err(async_graphql::Error::new("comment not found"));
        }
        if row.author_token_id != tok.id && !tok.is_admin {
            return Err(async_graphql::Error::new("not author"));
        }
        let deleted_at = chrono::Utc::now().to_rfc3339();
        state.db.execute("UPDATE comments SET deleted_at = $1 WHERE id = $2", params!(deleted_at, cid)).await.map_err(gerr)?;
        Ok(true)
    }

    /// Mirrors POST /admin/groups (groups.rs::create_group).
    async fn create_group(&self, gctx: &Context<'_>, name: String) -> GqlResult<Group> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let created_at = chrono::Utc::now().to_rfc3339();
        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO groups (name, created_at) VALUES ($1, $2) RETURNING id",
                params!(&name, created_at.clone()),
            )
            .await
            .map_err(gerr)?;
        Ok(Group { id: ID(id_row.id.to_string()), name, created_at })
    }

    /// Mirrors DELETE /admin/groups/{id} (groups.rs::delete_group).
    async fn delete_group(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let gid = parse_id(&id)?;
        state.db.execute("DELETE FROM group_members WHERE group_id = $1", params!(gid)).await.map_err(gerr)?;
        state.db.execute("DELETE FROM groups WHERE id = $1", params!(gid)).await.map_err(gerr)?;
        Ok(true)
    }

    /// Mirrors POST /admin/groups/{id}/members (groups.rs::add_member).
    async fn add_group_member(&self, gctx: &Context<'_>, group_id: ID, token_id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let gid = parse_id(&group_id)?;
        let tid = parse_id(&token_id)?;
        let created_at = chrono::Utc::now().to_rfc3339();
        state
            .db
            .execute(
                "INSERT INTO group_members (group_id, token_id, created_at) VALUES ($1, $2, $3) \
                 ON CONFLICT(group_id, token_id) DO NOTHING",
                params!(gid, tid, created_at),
            )
            .await
            .map_err(gerr)?;
        Ok(true)
    }

    /// Mirrors DELETE /admin/groups/{id}/members/{token_id} (groups.rs::remove_member).
    async fn remove_group_member(&self, gctx: &Context<'_>, group_id: ID, token_id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let gid = parse_id(&group_id)?;
        let tid = parse_id(&token_id)?;
        state
            .db
            .execute("DELETE FROM group_members WHERE group_id = $1 AND token_id = $2", params!(gid, tid))
            .await
            .map_err(gerr)?;
        Ok(true)
    }

    /// Mirrors POST /trash/{id} (trash.rs::restore).
    async fn restore_from_trash(&self, gctx: &Context<'_>, id: ID, resource_type: String) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&id)?;
        let table = gql_table_for(&resource_type)?;
        let owner = if tok.is_admin { None } else { Some(tok.id) };
        if !gql_check_owned_deleted(state, table, rid, owner).await? {
            return Err(async_graphql::Error::new("not found"));
        }
        let sql = format!("UPDATE {table} SET deleted_at = NULL WHERE id = $1");
        state.db.execute(sql, params!(rid)).await.map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "trash.restore", Some(table), Some(rid), None).await;
        Ok(true)
    }

    /// Mirrors DELETE /trash/{id} (trash.rs::purge).
    async fn purge_from_trash(&self, gctx: &Context<'_>, id: ID, resource_type: String) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let rid = parse_id(&id)?;
        let table = gql_table_for(&resource_type)?;
        let owner = if tok.is_admin { None } else { Some(tok.id) };
        if !gql_check_owned_deleted(state, table, rid, owner).await? {
            return Err(async_graphql::Error::new("not found"));
        }
        crate::trash::purge_resource(state, table, rid).await.map_err(|(_, msg)| async_graphql::Error::new(msg))?;
        crate::audit::log(&state.db, tok.id, "trash.purge", Some(table), Some(rid), None).await;
        Ok(true)
    }

    /// Mirrors PUT /retention-policy/mine (retention.rs::put_my_policy).
    async fn set_my_retention_policy(&self, gctx: &Context<'_>, trash_retention_days: i64) -> GqlResult<RetentionPolicy> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        gql_upsert_policy(&state.db, Some(tok.id), trash_retention_days).await?;
        Ok(RetentionPolicy { trash_retention_days })
    }

    /// Mirrors PUT /admin/retention-policy (retention.rs::put_global_policy).
    async fn set_global_retention_policy(&self, gctx: &Context<'_>, trash_retention_days: i64) -> GqlResult<RetentionPolicy> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        gql_upsert_policy(&state.db, None, trash_retention_days).await?;
        Ok(RetentionPolicy { trash_retention_days })
    }

    /// Mirrors DELETE /files/{id} (files.rs::delete_file); uses acl::check_access like the REST handler.
    async fn delete_file(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let fid = parse_id(&id)?;
        let exists: Option<IdRow> = state
            .db
            .query_map_optional("SELECT id FROM files WHERE id = $1 AND deleted_at IS NULL", params!(fid))
            .await
            .map_err(gerr)?;
        if exists.is_none() {
            return Err(async_graphql::Error::new("file not found"));
        }
        if !acl::check_access(&state.db, tok, "file", fid, acl::Action::Write).await {
            return Err(async_graphql::Error::new("file not found"));
        }
        let deleted_at = chrono::Utc::now().to_rfc3339();
        state.db.execute("UPDATE files SET deleted_at = $1 WHERE id = $2", params!(deleted_at, fid)).await.map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "file.delete", Some("file"), Some(fid), None).await;
        Ok(true)
    }

    /// Mirrors POST /files/{id}/restore (files.rs::restore); uses acl::check_access like the REST handler.
    async fn restore_file_version(&self, gctx: &Context<'_>, id: ID, version: i64) -> GqlResult<FileVersion> {
        let tok = ctx_of(gctx)?;
        let state = gctx.data::<AppState>()?;
        let fid = parse_id(&id)?;
        let exists: Option<IdRow> = state
            .db
            .query_map_optional("SELECT id FROM files WHERE id = $1 AND deleted_at IS NULL", params!(fid))
            .await
            .map_err(gerr)?;
        if exists.is_none() {
            return Err(async_graphql::Error::new("file not found"));
        }
        if !acl::check_access(&state.db, tok, "file", fid, acl::Action::Write).await {
            return Err(async_graphql::Error::new("file not found"));
        }

        struct SourceRow {
            size: i64,
            manifest: String,
        }
        impl From<&mut hiqlite::Row<'_>> for SourceRow {
            fn from(row: &mut hiqlite::Row<'_>) -> Self {
                Self { size: row.get("size"), manifest: row.get("manifest") }
            }
        }
        let source: Option<SourceRow> = state
            .db
            .query_map_optional(
                "SELECT size, manifest FROM file_versions WHERE file_id = $1 AND version_no = $2",
                params!(fid, version),
            )
            .await
            .map_err(gerr)?;
        let source = source.ok_or(async_graphql::Error::new("version not found"))?;

        let new_version_no = {
            let mut row = state
                .db
                .query_raw_one("SELECT MAX(version_no) AS max_ver FROM file_versions WHERE file_id = $1", params!(fid))
                .await
                .map_err(gerr)?;
            let max_ver: Option<i64> = row.get("max_ver");
            max_ver.unwrap_or(0) + 1
        };
        let created_at = chrono::Utc::now().to_rfc3339();

        let reused_manifest: Vec<String> = serde_json::from_str(&source.manifest).map_err(gerr)?;
        for hash in &reused_manifest {
            state.db.execute("UPDATE chunks SET refcount = refcount + 1 WHERE hash = $1", params!(hash)).await.map_err(gerr)?;
        }

        let new_version: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO file_versions (file_id, version_no, size, manifest, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                params!(fid, new_version_no, source.size, &source.manifest, created_at.clone()),
            )
            .await
            .map_err(gerr)?;
        state
            .db
            .execute("UPDATE files SET current_version_id = $1 WHERE id = $2", params!(new_version.id, fid))
            .await
            .map_err(gerr)?;

        crate::audit::log(&state.db, tok.id, "file.restore", Some("file"), Some(fid), Some(&version.to_string())).await;

        Ok(FileVersion {
            id: ID(new_version.id.to_string()),
            version_no: new_version_no,
            size: source.size,
            created_at,
        })
    }

    /// Mirrors POST /admin/storage-backends (storage_backends.rs::create_backend). `config`
    /// is a JSON-encoded string (parsed and validated server-side against `kind`) — GraphQL
    /// has no native free-form JSON scalar in this schema, so this follows the same
    /// String-carrying-JSON convention already used for `mentions`/`manifest` columns.
    async fn create_storage_backend(&self, gctx: &Context<'_>, name: String, kind: String, config: String) -> GqlResult<StorageBackend> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let config_val: serde_json::Value = serde_json::from_str(&config).map_err(|_| async_graphql::Error::new("config must be valid JSON"))?;
        gql_validate_backend_config(&kind, &config_val)?;
        let config_str = serde_json::to_string(&config_val).map_err(gerr)?;
        let created_at = chrono::Utc::now().to_rfc3339();

        let id_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO storage_backends (name, kind, config, is_active, created_at) VALUES ($1, $2, $3, 0, $4) RETURNING id",
                params!(&name, &kind, &config_str, &created_at),
            )
            .await
            .map_err(|_| async_graphql::Error::new("backend name already exists or db error"))?;

        crate::audit::log(&state.db, tok.id, "storage_backend.create", Some("storage_backend"), Some(id_row.id), None).await;

        Ok(StorageBackend {
            id: ID(id_row.id.to_string()),
            name,
            config: gql_redact_config(&kind, &config_str),
            kind,
            is_active: false,
            created_at,
        })
    }

    /// Mirrors DELETE /admin/storage-backends/{id} (storage_backends.rs::delete_backend):
    /// refuses to delete the currently-active backend.
    async fn delete_storage_backend(&self, gctx: &Context<'_>, id: ID) -> GqlResult<bool> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let bid = parse_id(&id)?;
        let row: Option<StorageBackendRow> = state
            .db
            .query_map_optional("SELECT id, name, kind, config, is_active, created_at FROM storage_backends WHERE id = $1", params!(bid))
            .await
            .map_err(gerr)?;
        let row = row.ok_or(async_graphql::Error::new("backend not found"))?;
        if row.is_active {
            return Err(async_graphql::Error::new("cannot delete the active backend; activate another backend first"));
        }
        state.db.execute("DELETE FROM storage_backends WHERE id = $1", params!(bid)).await.map_err(gerr)?;
        crate::audit::log(&state.db, tok.id, "storage_backend.delete", Some("storage_backend"), Some(bid), None).await;
        Ok(true)
    }

    /// Mirrors POST /admin/storage-backends/{id}/activate (storage_backends.rs::activate_backend):
    /// swaps `ChunkStore`'s live hot backend immediately (new writes only — see
    /// `ChunkStore::activate_backend`'s doc comment for the deliberate non-migration limitation).
    async fn activate_storage_backend(&self, gctx: &Context<'_>, id: ID) -> GqlResult<StorageBackend> {
        let tok = ctx_of(gctx)?;
        require_admin_gql(tok)?;
        let state = gctx.data::<AppState>()?;
        let bid = parse_id(&id)?;
        let row: Option<StorageBackendRow> = state
            .db
            .query_map_optional("SELECT id, name, kind, config, is_active, created_at FROM storage_backends WHERE id = $1", params!(bid))
            .await
            .map_err(gerr)?;
        let row = row.ok_or(async_graphql::Error::new("backend not found"))?;

        let config: serde_json::Value = serde_json::from_str(&row.config).map_err(gerr)?;
        state
            .storage
            .activate_backend(&row.kind, &config)
            .await
            .map_err(|_| async_graphql::Error::new("failed to build/activate backend (bad config?)"))?;

        state.db.execute("UPDATE storage_backends SET is_active = 0", params!()).await.map_err(gerr)?;
        state.db.execute("UPDATE storage_backends SET is_active = 1 WHERE id = $1", params!(bid)).await.map_err(gerr)?;

        crate::audit::log(&state.db, tok.id, "storage_backend.activate", Some("storage_backend"), Some(bid), None).await;

        Ok(StorageBackend {
            id: ID(row.id.to_string()),
            name: row.name,
            config: gql_redact_config(&row.kind, &row.config),
            kind: row.kind,
            is_active: true,
            created_at: row.created_at,
        })
    }
}

pub fn build_schema(db: hiqlite::Client) -> PlasteSchema {
    // db is unused directly here (queries go through AppState in resolvers via
    // request-scoped context data), kept as a param for callers that only have
    // the client handy; drop it to avoid an unused-var warning at call sites.
    drop(db);
    Schema::build(Query, Mutation, EmptySubscription).finish()
}

async fn graphql_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> Result<GraphQLResponse, (StatusCode, &'static str)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing authorization header"))?;

    let ctx: Option<TokenCtx> = state
        .db
        .query_map_optional(
            "SELECT id, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens WHERE token = $1",
            params!(token),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let ctx = ctx.ok_or((StatusCode::UNAUTHORIZED, "invalid token"))?;

    let schema = Schema::build(Query, Mutation, EmptySubscription).finish();
    let mut gql_req = req.into_inner();
    gql_req = gql_req.data(ctx).data(state);
    Ok(schema.execute(gql_req).await.into())
}

async fn playground() -> impl IntoResponse {
    Html(async_graphql::http::GraphiQLSource::build().endpoint("/graphql").finish())
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/graphql", get(playground).post(graphql_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::Request;

    async fn test_state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        crate::audit::init_schema(&db).await;
        crate::comments::init_schema(&db).await;
        crate::tags::init_schema(&db).await;
        crate::retention::init_schema(&db).await;
        crate::storage_backends::init_schema(&db).await;
        let created_at = chrono::Utc::now().to_rfc3339();
        db.execute(
            "INSERT INTO tokens (token, owner, is_admin, quota_bytes, created_at) VALUES ('tok-a', 'alice', 0, 1000000, $1)",
            params!(&created_at),
        )
        .await
        .unwrap();
        let state = AppState {
            db,
            storage: std::sync::Arc::new(crate::storage::ChunkStore::new(dir.path().join("chunks"))),
            chunks_dir: dir.path().join("chunks"),
            fts: std::sync::Arc::new(
                crate::fulltext::FullTextIndex::open_or_create(&dir.path().join("fts_index")).unwrap(),
            ),
        };
        // leak tempdir so the db file survives for the test's lifetime
        std::mem::forget(dir);
        state
    }

    async fn token_ctx(state: &AppState, token: &str) -> TokenCtx {
        let row: Option<TokenCtx> = state
            .db
            .query_map_optional(
                "SELECT id, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens WHERE token = $1",
                params!(token),
            )
            .await
            .unwrap();
        row.unwrap()
    }

    #[tokio::test]
    async fn create_and_query_folder() {
        let state = test_state().await;
        let ctx = token_ctx(&state, "tok-a").await;
        let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

        let mutation = r#"mutation { createFolder(name: "docs") { id name parentId } }"#;
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "mutation errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        let folder_id = json["createFolder"]["id"].as_str().unwrap().to_string();
        assert_eq!(json["createFolder"]["name"], "docs");

        let query = format!(r#"query {{ folder(id: "{folder_id}") {{ name }} }}"#);
        let req = Request::new(query).data(ctx).data(state);
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "query errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["folder"]["name"], "docs");
    }

    #[tokio::test]
    async fn missing_auth_context_rejected() {
        let state = test_state().await;
        let schema = Schema::build(Query, Mutation, EmptySubscription).finish();
        // No TokenCtx in context data -> resolver must return a GraphQL error, not panic.
        let req = Request::new(r#"query { folders { id } }"#).data(state);
        let resp = schema.execute(req).await;
        assert!(!resp.errors.is_empty());
        assert!(resp.errors[0].message.contains("unauthorized"));
    }

    async fn make_admin(state: &AppState) -> TokenCtx {
        let created_at = chrono::Utc::now().to_rfc3339();
        let token = uuid::Uuid::new_v4().to_string();
        state
            .db
            .execute(
                "INSERT INTO tokens (token, owner, is_admin, quota_bytes, created_at) VALUES ($1, 'admin', 1, 1000000, $2)",
                params!(&token, created_at),
            )
            .await
            .unwrap();
        token_ctx(state, &token).await
    }

    #[tokio::test]
    async fn create_token_admin_succeeds_non_admin_rejected() {
        let state = test_state().await;
        let admin = make_admin(&state).await;
        let user = token_ctx(&state, "tok-a").await;
        let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

        let mutation = r#"mutation { createToken(owner: "bob", durationDays: 10) { id owner token } }"#;
        let req = Request::new(mutation).data(admin).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "admin createToken errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["createToken"]["owner"], "bob");
        assert!(json["createToken"]["token"].as_str().unwrap().starts_with("plaste-"));

        let req = Request::new(mutation).data(user).data(state);
        let resp = schema.execute(req).await;
        assert!(!resp.errors.is_empty(), "non-admin createToken should be rejected");
    }

    #[tokio::test]
    async fn create_tag_attach_and_list_round_trip() {
        let state = test_state().await;
        let ctx = token_ctx(&state, "tok-a").await;
        let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

        let mutation = r#"mutation { createFolder(name: "docs") { id } }"#;
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty());
        let folder_id = serde_json::to_value(&resp.data).unwrap()["createFolder"]["id"].as_str().unwrap().to_string();

        let mutation = r#"mutation { createTag(name: "important") { id name } }"#;
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "createTag errors: {:?}", resp.errors);
        let tag_id = serde_json::to_value(&resp.data).unwrap()["createTag"]["id"].as_str().unwrap().to_string();

        let mutation = format!(
            r#"mutation {{ attachTag(resourceType: "folder", resourceId: "{folder_id}", tagId: "{tag_id}") {{ id }} }}"#
        );
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "attachTag errors: {:?}", resp.errors);

        let query = format!(r#"query {{ resourceTags(resourceType: "folder", resourceId: "{folder_id}") {{ name }} }}"#);
        let req = Request::new(query).data(ctx).data(state);
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "resourceTags errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["resourceTags"][0]["name"], "important");
    }

    #[tokio::test]
    async fn add_comment_and_list_round_trip() {
        let state = test_state().await;
        let ctx = token_ctx(&state, "tok-a").await;
        let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

        let mutation = r#"mutation { createFolder(name: "docs") { id } }"#;
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        let folder_id = serde_json::to_value(&resp.data).unwrap()["createFolder"]["id"].as_str().unwrap().to_string();

        let mutation = format!(
            r#"mutation {{ addComment(resourceType: "folder", resourceId: "{folder_id}", body: "hello @bob") {{ body mentions }} }}"#
        );
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "addComment errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["addComment"]["body"], "hello @bob");
        assert_eq!(json["addComment"]["mentions"][0], "bob");

        let query = format!(r#"query {{ comments(resourceType: "folder", resourceId: "{folder_id}") {{ body }} }}"#);
        let req = Request::new(query).data(ctx).data(state);
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "comments errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["comments"][0]["body"], "hello @bob");
    }

    #[tokio::test]
    async fn trash_query_and_restore_flow() {
        let state = test_state().await;
        let ctx = token_ctx(&state, "tok-a").await;
        let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

        let mutation = r#"mutation { createFolder(name: "docs") { id } }"#;
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        let folder_id = serde_json::to_value(&resp.data).unwrap()["createFolder"]["id"].as_str().unwrap().to_string();

        let mutation = format!(r#"mutation {{ deleteFolder(id: "{folder_id}") }}"#);
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "deleteFolder errors: {:?}", resp.errors);

        let query = r#"query { trash { folders { id name } files { id } } }"#;
        let req = Request::new(query).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "trash query errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["trash"]["folders"][0]["id"], folder_id);

        let mutation = format!(r#"mutation {{ restoreFromTrash(id: "{folder_id}", resourceType: "folder") }}"#);
        let req = Request::new(mutation).data(ctx.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "restoreFromTrash errors: {:?}", resp.errors);

        let query = format!(r#"query {{ folder(id: "{folder_id}") {{ name }} }}"#);
        let req = Request::new(query).data(ctx).data(state);
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty());
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["folder"]["name"], "docs");
    }

    #[tokio::test]
    async fn create_and_list_storage_backend_via_graphql() {
        let state = test_state().await;
        let admin = make_admin(&state).await;
        let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

        let mutation = r#"mutation { createStorageBackend(name: "gql-fs", kind: "fs", config: "{\"path\": \"./data/gql-chunks\"}") { id name isActive } }"#;
        let req = Request::new(mutation).data(admin.clone()).data(state.clone());
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "createStorageBackend errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["createStorageBackend"]["name"], "gql-fs");
        assert_eq!(json["createStorageBackend"]["isActive"], false);

        let query = r#"query { storageBackends { name kind isActive } }"#;
        let req = Request::new(query).data(admin).data(state);
        let resp = schema.execute(req).await;
        assert!(resp.errors.is_empty(), "storageBackends errors: {:?}", resp.errors);
        let json = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(json["storageBackends"][0]["name"], "gql-fs");
    }
}
