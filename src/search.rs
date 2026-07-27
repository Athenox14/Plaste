use axum::{extract::{Query, State}, http::StatusCode, Json, Router};
use hiqlite::params;
use serde::{Deserialize, Serialize};

use crate::{auth::TokenCtx, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/search", axum::routing::get(search))
}

type ApiErr = (StatusCode, &'static str);

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

#[derive(Serialize)]
struct FolderHit {
    id: i64,
    name: String,
    parent_id: Option<i64>,
}

struct FolderHitRow {
    id: i64,
    name: String,
    parent_id: Option<i64>,
}
impl From<&mut hiqlite::Row<'_>> for FolderHitRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            parent_id: row.get("parent_id"),
        }
    }
}

#[derive(Serialize)]
struct FileHit {
    id: i64,
    name: String,
    folder_id: Option<i64>,
}

struct FileHitRow {
    id: i64,
    name: String,
    folder_id: Option<i64>,
}
impl From<&mut hiqlite::Row<'_>> for FileHitRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            folder_id: row.get("folder_id"),
        }
    }
}

#[derive(Serialize)]
struct SearchResp {
    folders: Vec<FolderHit>,
    files: Vec<FileHit>,
}

// Files: tantivy full-text (name+content) ranked search, plus a LIKE fallback
// for files predating/missing from the FTS index. Folders: still naive LIKE
// (no content to search, fine at MVP scale).
async fn search(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Query(q): Query<SearchQuery>,
) -> Result<Json<SearchResp>, ApiErr> {
    let term = q.q.unwrap_or_default();
    if term.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "missing q"));
    }

    let folders: Vec<FolderHitRow> = if ctx.is_admin {
        state
            .db
            .query_map(
                "SELECT id, name, parent_id FROM folders \
                 WHERE deleted_at IS NULL AND name LIKE '%' || $1 || '%' COLLATE NOCASE \
                 LIMIT 100",
                params!(&term),
            )
            .await
    } else {
        state
            .db
            .query_map(
                "SELECT id, name, parent_id FROM folders \
                 WHERE deleted_at IS NULL AND owner_token_id = $1 \
                 AND name LIKE '%' || $2 || '%' COLLATE NOCASE \
                 LIMIT 100",
                params!(ctx.id, &term),
            )
            .await
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    // Candidate file ids from tantivy (names + content), ranked by relevance;
    // cross-checked against the DB below for deleted_at/owner since the FTS
    // index isn't purged on soft-delete (files can be restored from trash).
    let candidate_ids = state.fts.search(ctx.id, ctx.is_admin, &term, 100);

    let mut files: Vec<FileHitRow> = Vec::new();
    for id in candidate_ids {
        let row: Option<FileHitRow> = if ctx.is_admin {
            state
                .db
                .query_map_optional(
                    "SELECT id, name, folder_id FROM files WHERE id = $1 AND deleted_at IS NULL",
                    params!(id),
                )
                .await
        } else {
            state
                .db
                .query_map_optional(
                    "SELECT id, name, folder_id FROM files \
                     WHERE id = $1 AND deleted_at IS NULL AND owner_token_id = $2",
                    params!(id, ctx.id),
                )
                .await
        }
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        if let Some(r) = row {
            files.push(r);
        }
    }

    // Fall back to the plain LIKE match on name too, in case a file predates
    // the FTS index or its content wasn't extractable — dedup by id.
    let like_files: Vec<FileHitRow> = if ctx.is_admin {
        state
            .db
            .query_map(
                "SELECT id, name, folder_id FROM files \
                 WHERE deleted_at IS NULL AND name LIKE '%' || $1 || '%' COLLATE NOCASE \
                 LIMIT 100",
                params!(&term),
            )
            .await
    } else {
        state
            .db
            .query_map(
                "SELECT id, name, folder_id FROM files \
                 WHERE deleted_at IS NULL AND owner_token_id = $1 \
                 AND name LIKE '%' || $2 || '%' COLLATE NOCASE \
                 LIMIT 100",
                params!(ctx.id, &term),
            )
            .await
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let seen: std::collections::HashSet<i64> = files.iter().map(|f| f.id).collect();
    for f in like_files {
        if !seen.contains(&f.id) {
            files.push(f);
        }
    }

    Ok(Json(SearchResp {
        folders: folders
            .into_iter()
            .map(|r| FolderHit { id: r.id, name: r.name, parent_id: r.parent_id })
            .collect(),
        files: files
            .into_iter()
            .map(|r| FileHit { id: r.id, name: r.name, folder_id: r.folder_id })
            .collect(),
    }))
}
