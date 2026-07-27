//! Minimal MCP (Model Context Protocol) server: hand-rolled JSON-RPC 2.0 over
//! HTTP, mounted at POST /mcp. Implements `initialize`, `tools/list`, `tools/call`.
//!
//! ponytail: skipped the `rmcp` crate. Its axum integration targets stateful
//! stdio/SSE session servers and would mean threading a second router/service
//! type alongside the existing `Router<AppState>` merge in main.rs (which
//! another agent is editing right now) for very little payoff: MCP's wire
//! format is just JSON-RPC 2.0 with three method names, documented plainly at
//! modelcontextprotocol.io. A single stateless axum handler is a smaller,
//! lower-risk diff and merges cleanly. Revisit rmcp if stdio transport or
//! resources/prompts (not just tools) are ever needed.
use axum::{extract::State, http::HeaderMap, Json, Router};
use hiqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::TokenCtx, db::IdRow, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/mcp", axum::routing::post(handle))
}

/// Row shape for `SELECT owner_token_id, deleted_at FROM folders WHERE id = $1`.
struct OwnerRow {
    owner_token_id: i64,
    deleted_at: Option<String>,
}
impl From<&mut hiqlite::Row<'_>> for OwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { owner_token_id: row.get("owner_token_id"), deleted_at: row.get("deleted_at") }
    }
}

#[derive(Deserialize)]
struct RpcRequest {
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

fn ok(id: Value, result: Value) -> Json<Value> {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn err(id: Value, code: i64, message: &str) -> Json<Value> {
    Json(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }))
}

fn tool_defs() -> Value {
    json!([
        {
            "name": "list_folders",
            "description": "List folders and files at a given level (same data as GET /folders).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "parent_id": {"type": "integer", "description": "Optional parent folder id; omit for root."},
                    "token": {"type": "string", "description": "Plaste API token."}
                },
                "required": ["token"]
            }
        },
        {
            "name": "search_files",
            "description": "Search folders and files by name substring (same as GET /search?q=).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "token": {"type": "string"}
                },
                "required": ["query", "token"]
            }
        },
        {
            "name": "get_file_versions",
            "description": "List versions of a file (same as GET /files/{id}/versions).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_id": {"type": "integer"},
                    "token": {"type": "string"}
                },
                "required": ["file_id", "token"]
            }
        },
        {
            "name": "create_folder",
            "description": "Create a folder (same as POST /folders).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "parent_id": {"type": "integer"},
                    "token": {"type": "string"}
                },
                "required": ["name", "token"]
            }
        }
    ])
}

/// Authenticates a token string directly against the `tokens` table, mirroring
/// `auth::TokenCtx`'s bearer-header lookup — this transport passes the token as
/// a tool argument instead of a header.
async fn ctx_for_token(state: &AppState, token: &str) -> Result<TokenCtx, String> {
    let ctx: Option<TokenCtx> = state
        .db
        .query_map_optional(
            "SELECT id, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens WHERE token = $1",
            params!(token),
        )
        .await
        .map_err(|_| "db error".to_string())?;
    ctx.ok_or_else(|| "invalid token".to_string())
}

struct SubFolderRow {
    id: i64,
    name: String,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for SubFolderRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id"), name: row.get("name"), created_at: row.get("created_at") }
    }
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

async fn tool_list_folders(state: &AppState, ctx: &TokenCtx, parent_id: Option<i64>) -> Result<Value, String> {
    let (folders, files): (Vec<SubFolderRow>, Vec<FileEntryRow>) = if let Some(pid) = parent_id {
        // Ownership check on the target folder, same as folders::fetch_folder + check_access.
        let owner: Option<OwnerRow> = state
            .db
            .query_map_optional("SELECT owner_token_id, deleted_at FROM folders WHERE id = $1", params!(pid))
            .await
            .map_err(|_| "db error".to_string())?;
        let owner = owner.ok_or("folder not found".to_string())?;
        if owner.deleted_at.is_some() {
            return Err("folder not found".to_string());
        }
        if owner.owner_token_id != ctx.id && !ctx.is_admin {
            return Err("not owner".to_string());
        }

        let folders = state
            .db
            .query_map(
                "SELECT id, name, created_at FROM folders WHERE parent_id = $1 AND deleted_at IS NULL",
                params!(pid),
            )
            .await
            .map_err(|_| "db error".to_string())?;
        let files = state
            .db
            .query_map(
                "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS size, f.created_at AS created_at \
                 FROM files f LEFT JOIN file_versions v ON v.id = f.current_version_id \
                 WHERE f.folder_id = $1 AND f.deleted_at IS NULL",
                params!(pid),
            )
            .await
            .map_err(|_| "db error".to_string())?;
        (folders, files)
    } else {
        let folders = state
            .db
            .query_map(
                "SELECT id, name, created_at FROM folders WHERE parent_id IS NULL AND owner_token_id = $1 AND deleted_at IS NULL",
                params!(ctx.id),
            )
            .await
            .map_err(|_| "db error".to_string())?;
        let files = state
            .db
            .query_map(
                "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS size, f.created_at AS created_at \
                 FROM files f LEFT JOIN file_versions v ON v.id = f.current_version_id \
                 WHERE f.folder_id IS NULL AND f.owner_token_id = $1 AND f.deleted_at IS NULL",
                params!(ctx.id),
            )
            .await
            .map_err(|_| "db error".to_string())?;
        (folders, files)
    };

    Ok(json!({
        "folders": folders.into_iter().map(|r| json!({"id": r.id, "name": r.name, "created_at": r.created_at})).collect::<Vec<_>>(),
        "files": files.into_iter().map(|r| json!({"id": r.id, "name": r.name, "size": r.size, "created_at": r.created_at})).collect::<Vec<_>>(),
    }))
}

struct FolderHitRow {
    id: i64,
    name: String,
    parent_id: Option<i64>,
}
impl From<&mut hiqlite::Row<'_>> for FolderHitRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id"), name: row.get("name"), parent_id: row.get("parent_id") }
    }
}
struct FileHitRow {
    id: i64,
    name: String,
    folder_id: Option<i64>,
}
impl From<&mut hiqlite::Row<'_>> for FileHitRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id"), name: row.get("name"), folder_id: row.get("folder_id") }
    }
}

async fn tool_search_files(state: &AppState, ctx: &TokenCtx, query: &str) -> Result<Value, String> {
    if query.trim().is_empty() {
        return Err("missing query".to_string());
    }
    let folders: Vec<FolderHitRow> = if ctx.is_admin {
        state
            .db
            .query_map(
                "SELECT id, name, parent_id FROM folders WHERE deleted_at IS NULL AND name LIKE '%' || $1 || '%' COLLATE NOCASE LIMIT 100",
                params!(query),
            )
            .await
    } else {
        state
            .db
            .query_map(
                "SELECT id, name, parent_id FROM folders WHERE deleted_at IS NULL AND owner_token_id = $1 AND name LIKE '%' || $2 || '%' COLLATE NOCASE LIMIT 100",
                params!(ctx.id, query),
            )
            .await
    }
    .map_err(|_| "db error".to_string())?;

    let files: Vec<FileHitRow> = if ctx.is_admin {
        state
            .db
            .query_map(
                "SELECT id, name, folder_id FROM files WHERE deleted_at IS NULL AND name LIKE '%' || $1 || '%' COLLATE NOCASE LIMIT 100",
                params!(query),
            )
            .await
    } else {
        state
            .db
            .query_map(
                "SELECT id, name, folder_id FROM files WHERE deleted_at IS NULL AND owner_token_id = $1 AND name LIKE '%' || $2 || '%' COLLATE NOCASE LIMIT 100",
                params!(ctx.id, query),
            )
            .await
    }
    .map_err(|_| "db error".to_string())?;

    Ok(json!({
        "folders": folders.into_iter().map(|r| json!({"id": r.id, "name": r.name, "parent_id": r.parent_id})).collect::<Vec<_>>(),
        "files": files.into_iter().map(|r| json!({"id": r.id, "name": r.name, "folder_id": r.folder_id})).collect::<Vec<_>>(),
    }))
}

struct FileOwnerRow {
    owner_token_id: i64,
}
impl From<&mut hiqlite::Row<'_>> for FileOwnerRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { owner_token_id: row.get("owner_token_id") }
    }
}
struct VersionRow {
    id: i64,
    version_no: i64,
    size: i64,
    created_at: String,
}
impl From<&mut hiqlite::Row<'_>> for VersionRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            version_no: row.get("version_no"),
            size: row.get("size"),
            created_at: row.get("created_at"),
        }
    }
}

async fn tool_get_file_versions(state: &AppState, ctx: &TokenCtx, file_id: i64) -> Result<Value, String> {
    let file: Option<FileOwnerRow> = state
        .db
        .query_map_optional(
            "SELECT owner_token_id FROM files WHERE id = $1 AND deleted_at IS NULL",
            params!(file_id),
        )
        .await
        .map_err(|_| "db error".to_string())?;
    let file = file.ok_or("file not found".to_string())?;
    if !ctx.is_admin && file.owner_token_id != ctx.id {
        return Err("file not found".to_string());
    }

    let rows: Vec<VersionRow> = state
        .db
        .query_map(
            "SELECT id, version_no, size, manifest, created_at FROM file_versions WHERE file_id = $1 ORDER BY version_no",
            params!(file_id),
        )
        .await
        .map_err(|_| "db error".to_string())?;

    Ok(json!(rows
        .into_iter()
        .map(|v| json!({"id": v.id, "version_no": v.version_no, "size": v.size, "created_at": v.created_at}))
        .collect::<Vec<_>>()))
}

async fn tool_create_folder(
    state: &AppState,
    ctx: &TokenCtx,
    name: &str,
    parent_id: Option<i64>,
) -> Result<Value, String> {
    if let Some(pid) = parent_id {
        let owner: Option<OwnerRow> = state
            .db
            .query_map_optional("SELECT owner_token_id, deleted_at FROM folders WHERE id = $1", params!(pid))
            .await
            .map_err(|_| "db error".to_string())?;
        let owner = owner.ok_or("parent folder not found".to_string())?;
        if owner.deleted_at.is_some() {
            return Err("parent folder not found".to_string());
        }
        if owner.owner_token_id != ctx.id && !ctx.is_admin {
            return Err("not owner".to_string());
        }
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO folders (parent_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
            params!(parent_id, name, ctx.id, created_at),
        )
        .await
        .map_err(|_| "db error".to_string())?;

    crate::audit::log(&state.db, ctx.id, "folder.create", Some("folder"), Some(id_row.id), None).await;

    Ok(json!({"id": id_row.id, "name": name, "parent_id": parent_id}))
}

/// Wraps a tool result/error as an MCP `tools/call` result payload
/// (`{content: [{type: "text", text: ...}], isError: bool}`).
fn tool_result(result: Result<Value, String>) -> Value {
    match result {
        Ok(v) => json!({
            "content": [{"type": "text", "text": v.to_string()}],
            "isError": false
        }),
        Err(e) => json!({
            "content": [{"type": "text", "text": e}],
            "isError": true
        }),
    }
}

async fn dispatch_tool(state: &AppState, name: &str, args: &Value) -> Value {
    let token = args.get("token").and_then(|v| v.as_str()).unwrap_or_default();
    let ctx = match ctx_for_token(state, token).await {
        Ok(c) => c,
        Err(e) => return tool_result(Err(e)),
    };

    let result = match name {
        "list_folders" => {
            let parent_id = args.get("parent_id").and_then(|v| v.as_i64());
            tool_list_folders(state, &ctx, parent_id).await
        }
        "search_files" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or_default();
            tool_search_files(state, &ctx, query).await
        }
        "get_file_versions" => match args.get("file_id").and_then(|v| v.as_i64()) {
            Some(file_id) => tool_get_file_versions(state, &ctx, file_id).await,
            None => Err("missing file_id".to_string()),
        },
        "create_folder" => match args.get("name").and_then(|v| v.as_str()) {
            Some(name) => {
                let parent_id = args.get("parent_id").and_then(|v| v.as_i64());
                tool_create_folder(state, &ctx, name, parent_id).await
            }
            None => Err("missing name".to_string()),
        },
        other => Err(format!("unknown tool: {other}")),
    };

    tool_result(result)
}

async fn handle(State(state): State<AppState>, _headers: HeaderMap, Json(req): Json<RpcRequest>) -> Json<Value> {
    match req.method.as_str() {
        "initialize" => ok(
            req.id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "plaste-mcp", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "tools/list" => ok(req.id, json!({ "tools": tool_defs() })),
        "tools/call" => {
            let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            let args = req.params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let result = dispatch_tool(&state, name, &args).await;
            ok(req.id, result)
        }
        other => err(req.id, -32601, &format!("method not found: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        crate::audit::init_schema(&db).await;
        let storage_dir = dir.path().join("chunks");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();
        let fts_dir = dir.path().join("fts_index");
        AppState {
            db,
            storage: std::sync::Arc::new(crate::storage::ChunkStore::new(storage_dir.clone())),
            chunks_dir: storage_dir,
            fts: std::sync::Arc::new(
                crate::fulltext::FullTextIndex::open_or_create(&fts_dir).unwrap(),
            ),
        }
        // NB: `dir` (tempdir) intentionally leaked for the test's lifetime by
        // being dropped here is fine — hiqlite has already opened its files;
        // Windows temp cleanup isn't asserted on by this test.
    }

    async fn post(app: axum::Router, body: Value) -> Value {
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn tools_list_returns_four_tools() {
        let state = test_state().await;
        let app = router().with_state(state);
        let resp = post(app, json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).await;
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"list_folders"));
        assert!(names.contains(&"search_files"));
        assert!(names.contains(&"get_file_versions"));
        assert!(names.contains(&"create_folder"));
    }

    #[tokio::test]
    async fn tools_call_search_files_with_invalid_token_is_error() {
        let state = test_state().await;
        let app = router().with_state(state);
        let resp = post(
            app,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "search_files", "arguments": {"query": "foo", "token": "nope"}}
            }),
        )
        .await;
        assert_eq!(resp["id"], 2);
        assert_eq!(resp["result"]["isError"], true);
    }

    #[tokio::test]
    async fn tools_call_search_files_with_valid_token_returns_empty() {
        let state = test_state().await;

        // Seed an admin token directly (mirrors auth::bootstrap_admin).
        let created_at = chrono::Utc::now().to_rfc3339();
        state
            .db
            .execute(
                "INSERT INTO tokens (token, owner, is_admin, quota_bytes, created_at) VALUES ($1, 'admin', 1, 1099511627776, $2)",
                params!("test-token", created_at),
            )
            .await
            .unwrap();

        let app = router().with_state(state);
        let resp = post(
            app,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "search_files", "arguments": {"query": "nonexistent", "token": "test-token"}}
            }),
        )
        .await;
        assert_eq!(resp["id"], 3);
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["folders"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["files"].as_array().unwrap().len(), 0);
    }
}
