use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::Serialize;

use crate::{auth::{require_admin, TokenCtx}, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/admin/rotate-key", post(rotate_key))
}

#[derive(Serialize)]
struct RotateKeyResp {
    new_key_id: String,
}

async fn rotate_key(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<RotateKeyResp>, (StatusCode, &'static str)> {
    require_admin(&ctx)?;
    let new_key_id = state
        .storage
        .rotate_key()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "key rotation failed"))?;
    Ok(Json(RotateKeyResp { new_key_id }))
}
