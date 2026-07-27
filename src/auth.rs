use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
};
use hiqlite::params;

use crate::AppState;

#[derive(Clone, Debug)]
pub struct TokenCtx {
    pub id: i64,
    pub owner: String,
    pub is_admin: bool,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub expires_at: Option<String>,
}

impl From<&mut hiqlite::Row<'_>> for TokenCtx {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            owner: row.get("owner"),
            is_admin: row.get::<i64>("is_admin") != 0,
            quota_bytes: row.get("quota_bytes"),
            used_bytes: row.get("used_bytes"),
            expires_at: row.get("expires_at"),
        }
    }
}

/// Returns true if `expires_at` (an rfc3339 timestamp, if present) is in the past.
fn is_expired(expires_at: &Option<String>) -> bool {
    expires_at
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .is_some_and(|t| t < chrono::Utc::now())
}

impl FromRequestParts<AppState> for TokenCtx {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "missing authorization header"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "expected Bearer token"))?;

        let ctx: Option<TokenCtx> = state
            .db
            .query_map_optional(
                "SELECT id, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens WHERE token = $1",
                params!(token),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

        let ctx = ctx.ok_or((StatusCode::UNAUTHORIZED, "invalid token"))?;
        if is_expired(&ctx.expires_at) {
            return Err((StatusCode::UNAUTHORIZED, "token expired"));
        }
        Ok(ctx)
    }
}

pub fn require_admin(ctx: &TokenCtx) -> Result<(), (StatusCode, &'static str)> {
    if ctx.is_admin {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "admin token required"))
    }
}

#[allow(dead_code)]
pub async fn bootstrap_admin(state: &AppState) {
    let mut count_row = state
        .db
        .query_raw_one("SELECT COUNT(*) AS count FROM tokens", params!())
        .await
        .unwrap();
    let count: i64 = count_row.get("count");
    if count == 0 {
        let token = std::env::var("PLASTE_ADMIN_TOKEN")
            .unwrap_or_else(|_| format!("admin-{}", uuid::Uuid::new_v4()));
        let created_at = chrono::Utc::now().to_rfc3339();
        state
            .db
            .execute(
                "INSERT INTO tokens (token, owner, is_admin, quota_bytes, created_at) VALUES ($1, 'admin', 1, 1099511627776, $2)",
                params!(&token, created_at),
            )
            .await
            .unwrap();
        tracing::info!("bootstrap admin token: {token}");
        println!("PLASTE ADMIN TOKEN: {token}");
    }
}

#[allow(unused)]
type _Unused = State<AppState>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn setup() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
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

    async fn insert_token(db: &hiqlite::Client, expires_at: Option<String>) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        db.execute(
            "INSERT INTO tokens (token, owner, created_at, expires_at) VALUES ($1, 'u', $2, $3)",
            params!(&token, chrono::Utc::now().to_rfc3339(), expires_at),
        )
        .await
        .unwrap();
        token
    }

    async fn whoami(_ctx: TokenCtx) -> &'static str {
        "ok"
    }

    fn test_router() -> Router<AppState> {
        Router::new().route("/whoami", get(whoami))
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (state, _dir) = setup().await;
        let past = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let token = insert_token(&state.db, Some(past)).await;

        let app = test_router().with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"token expired");
    }

    #[tokio::test]
    async fn token_with_no_expiry_or_future_expiry_works() {
        let (state, _dir) = setup().await;
        let no_expiry = insert_token(&state.db, None).await;
        let future = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let future_expiry = insert_token(&state.db, Some(future)).await;

        for token in [no_expiry, future_expiry] {
            let app = test_router().with_state(state.clone());
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/whoami")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }
}
