use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{post, delete, put}, Json, Router};
use hiqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::{require_admin, TokenCtx}, db::IdRow, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/tokens", post(create_token).get(list_tokens))
        .route("/admin/tokens/{id}", delete(delete_token))
        .route("/admin/tokens/{id}/renew", put(renew_token))
        .route("/admin/tokens/{id}/rotate", post(rotate_token))
}

fn default_duration_days() -> i64 {
    30
}

#[derive(Deserialize)]
struct CreateTokenReq {
    owner: String,
    #[serde(default)]
    is_admin: bool,
    #[serde(default = "default_quota")]
    quota_bytes: i64,
    #[serde(default = "default_duration_days")]
    duration_days: i64,
}
fn default_quota() -> i64 {
    10 * 1024 * 1024 * 1024
}

#[derive(Deserialize)]
struct RenewTokenReq {
    duration_days: i64,
}

#[derive(Serialize)]
struct TokenResp {
    id: i64,
    token: String,
    owner: String,
    is_admin: bool,
    quota_bytes: i64,
    used_bytes: i64,
    expires_at: Option<String>,
}

/// Row shape for `SELECT id, token, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens`.
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

async fn create_token(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Json(req): Json<CreateTokenReq>,
) -> Result<Json<TokenResp>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let token = format!("plaste-{}", Uuid::new_v4());
    let created_at = chrono::Utc::now();
    let expires_at = created_at + chrono::Duration::days(req.duration_days);
    let created_at = created_at.to_rfc3339();
    let expires_at = expires_at.to_rfc3339();

    let id_row: IdRow = state
        .db
        .execute_returning_map_one(
            "INSERT INTO tokens (token, owner, is_admin, quota_bytes, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            params!(&token, &req.owner, req.is_admin, req.quota_bytes, created_at, &expires_at),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    crate::audit::log(&state.db, ctx.id, "token.create", Some("token"), Some(id_row.id), None).await;

    Ok(Json(TokenResp {
        id: id_row.id,
        token,
        owner: req.owner,
        is_admin: req.is_admin,
        quota_bytes: req.quota_bytes,
        used_bytes: 0,
        expires_at: Some(expires_at),
    }))
}

async fn list_tokens(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<Vec<TokenResp>>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let rows: Vec<TokenRow> = state
        .db
        .query_map(
            "SELECT id, token, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens",
            params!(),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| TokenResp {
                id: r.id,
                token: r.token,
                owner: r.owner,
                is_admin: r.is_admin,
                quota_bytes: r.quota_bytes,
                used_bytes: r.used_bytes,
                expires_at: r.expires_at,
            })
            .collect(),
    ))
}

async fn renew_token(
    State(state): State<AppState>,
    ctx: TokenCtx,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(req): Json<RenewTokenReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(req.duration_days)).to_rfc3339();
    state
        .db
        .execute(
            "UPDATE tokens SET expires_at = $1 WHERE id = $2",
            params!(&expires_at, id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    crate::audit::log(&state.db, ctx.id, "token.renew", Some("token"), Some(id), None).await;
    Ok(Json(serde_json::json!({ "id": id, "expires_at": expires_at })))
}

/// Remplace le SECRET d'un jeton en gardant sa ligne — donc son `id`.
///
/// POURQUOI PAS « supprimer puis recreer ». Tout ce que possede un compte est
/// rattache a `owner_token_id` : `folders`, `files`, `tus_uploads`, les
/// permissions. Un nouveau jeton recevrait un nouvel `id` et l'utilisateur
/// retrouverait un espace VIDE, ses fichiers devenus inaccessibles. La rotation
/// doit donc conserver l'identite du jeton et ne changer que la chaine secrete.
///
/// L'ancien secret cesse de fonctionner immediatement : c'est le but quand il a
/// fuite. Les clients qui l'utilisaient prendront un 401 et devront recuperer le
/// nouveau.
async fn rotate_token(
    State(state): State<AppState>,
    ctx: TokenCtx,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let nouveau = format!("plaste-{}", Uuid::new_v4());

    // `rows_affected` a 0 = jeton inexistant. Sans cette verification on
    // renverrait un secret tout neuf qui n'authentifie rien.
    let touchees = state
        .db
        .execute(
            "UPDATE tokens SET token = $1 WHERE id = $2",
            params!(&nouveau, id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    if touchees == 0 {
        return Err((StatusCode::NOT_FOUND, "token not found"));
    }

    crate::audit::log(&state.db, ctx.id, "token.rotate", Some("token"), Some(id), None).await;

    Ok(Json(serde_json::json!({ "id": id, "token": nouveau })))
}

async fn delete_token(
    State(state): State<AppState>,
    ctx: TokenCtx,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    state
        .db
        .execute("DELETE FROM tokens WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    crate::audit::log(&state.db, ctx.id, "token.delete", Some("token"), Some(id), None).await;
    Ok(StatusCode::NO_CONTENT)
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

    /// L'invariant qui compte : la rotation change le secret mais PAS l'`id`.
    /// Tout ce que possede un compte pend a `owner_token_id` ; si l'id bougeait,
    /// l'utilisateur retrouverait un espace vide.
    #[tokio::test]
    async fn rotate_change_le_secret_mais_pas_l_id() {
        let (state, _dir) = setup().await;
        let admin_token = make_admin_token(&state.db).await;

        let app = router().with_state(state.clone());
        let creation = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tokens")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"owner":"u","duration_days":30}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let corps = axum::body::to_bytes(creation.into_body(), usize::MAX).await.unwrap();
        let cree: serde_json::Value = serde_json::from_slice(&corps).unwrap();
        let id = cree["id"].as_i64().unwrap();
        let ancien = cree["token"].as_str().unwrap().to_string();

        let app = router().with_state(state.clone());
        let rotation = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/tokens/{id}/rotate"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rotation.status(), StatusCode::OK);
        let corps = axum::body::to_bytes(rotation.into_body(), usize::MAX).await.unwrap();
        let tourne: serde_json::Value = serde_json::from_slice(&corps).unwrap();

        assert_eq!(tourne["id"].as_i64().unwrap(), id, "l'id doit etre preserve");
        let nouveau = tourne["token"].as_str().unwrap();
        assert_ne!(nouveau, ancien, "le secret doit changer");

        // L'ancien secret n'authentifie plus rien, le nouveau porte le meme id.
        let restant: Option<crate::auth::TokenCtx> = state
            .db
            .query_map_optional(
                "SELECT id, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens WHERE token = $1",
                params!(&ancien),
            )
            .await
            .unwrap();
        assert!(restant.is_none(), "l'ancien secret doit cesser de fonctionner");

        let actuel: crate::auth::TokenCtx = state
            .db
            .query_map_one(
                "SELECT id, owner, is_admin, quota_bytes, used_bytes, expires_at FROM tokens WHERE token = $1",
                params!(nouveau),
            )
            .await
            .unwrap();
        assert_eq!(actuel.id, id);
    }

    #[tokio::test]
    async fn renew_extends_expiry() {
        let (state, _dir) = setup().await;
        let admin_token = make_admin_token(&state.db).await;

        // Create a token with a short duration.
        let app = router().with_state(state.clone());
        let create_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tokens")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"owner":"u","duration_days":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(create_resp.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = created["id"].as_i64().unwrap();
        let original_expiry = created["expires_at"].as_str().unwrap().to_string();

        // Renew it for 365 days.
        let app = router().with_state(state.clone());
        let renew_resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/admin/tokens/{id}/renew"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"duration_days":365}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(renew_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(renew_resp.into_body(), usize::MAX).await.unwrap();
        let renewed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let new_expiry = renewed["expires_at"].as_str().unwrap().to_string();

        assert!(new_expiry > original_expiry, "renewed expiry should be later than the original");
    }
}
