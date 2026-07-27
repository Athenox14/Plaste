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

use crate::{auth::TokenCtx, db::IdRow, AppState};

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
}
