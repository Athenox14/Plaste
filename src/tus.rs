//! tus 1.0.0 resumable upload protocol (Creation + Core + Termination extensions),
//! hand-implemented against axum per https://tus.io/protocols/resumable-upload.
//!
//! Own schema, run separately from db.rs's SCHEMA array (see main.rs merge note) to avoid
//! touching code other agents are editing. Partial upload bytes are appended to a plain file
//! under `<data_dir>/tus_partial/<upload_id>` (NOT through ChunkStore/CDC); only once the
//! upload is complete do we read the assembled file and run it through the normal
//! chunking+versioning pipeline.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use hiqlite::params;
use tokio::io::AsyncWriteExt;

use crate::{auth::TokenCtx, db::IdRow, AppState};

const TUS_VERSION: &str = "1.0.0";
const TUS_MAX_SIZE: i64 = 5 * 1024 * 1024 * 1024; // 5GB cap

pub async fn init_schema(db: &hiqlite::Client) {
    const SCHEMA: &[&str] = &[r#"CREATE TABLE IF NOT EXISTS tus_uploads (
        id TEXT PRIMARY KEY,
        owner_token_id INTEGER NOT NULL,
        folder_id INTEGER,
        name TEXT NOT NULL,
        total_size INTEGER NOT NULL,
        uploaded_bytes INTEGER NOT NULL DEFAULT 0,
        metadata TEXT,
        created_at TEXT NOT NULL,
        completed INTEGER NOT NULL DEFAULT 0,
        expected_base_version INTEGER
    )"#];
    for stmt in SCHEMA {
        db.execute(*stmt, params!()).await.expect("tus schema init");
    }
    if let Err(e) = db
        .execute("ALTER TABLE tus_uploads ADD COLUMN expected_base_version INTEGER", params!())
        .await
    {
        tracing::debug!("skipping ALTER (likely already applied): {e}");
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/tus/uploads", post(create_upload).options(discovery))
        .route(
            "/tus/uploads/{id}",
            axum::routing::head(head_upload)
                .patch(patch_upload)
                .delete(delete_upload)
                .options(discovery),
        )
}

type ApiErr = (StatusCode, &'static str);

fn data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("PLASTE_DATA_DIR").unwrap_or_else(|_| "./data".to_string()))
}

fn partial_dir() -> std::path::PathBuf {
    data_dir().join("tus_partial")
}

fn partial_path(id: &str) -> std::path::PathBuf {
    partial_dir().join(id)
}

struct UploadRow {
    id: String,
    owner_token_id: i64,
    folder_id: Option<i64>,
    name: String,
    total_size: i64,
    uploaded_bytes: i64,
    completed: i64,
    expected_base_version: Option<i64>,
}
impl From<&mut hiqlite::Row<'_>> for UploadRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            owner_token_id: row.get("owner_token_id"),
            folder_id: row.get("folder_id"),
            name: row.get("name"),
            total_size: row.get("total_size"),
            uploaded_bytes: row.get("uploaded_bytes"),
            completed: row.get("completed"),
            expected_base_version: row.get("expected_base_version"),
        }
    }
}


async fn get_owned_upload(state: &AppState, ctx: &TokenCtx, id: &str) -> Result<UploadRow, ApiErr> {
    let row: Option<UploadRow> = state
        .db
        .query_map_optional(
            "SELECT id, owner_token_id, folder_id, name, total_size, uploaded_bytes, completed, expected_base_version FROM tus_uploads WHERE id = $1",
            params!(id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let row = row.ok_or((StatusCode::NOT_FOUND, "upload not found"))?;
    if row.owner_token_id != ctx.id && !ctx.is_admin {
        return Err((StatusCode::NOT_FOUND, "upload not found"));
    }
    Ok(row)
}

fn tus_headers() -> [(&'static str, &'static str); 1] {
    [("Tus-Resumable", TUS_VERSION)]
}

// ---------- discovery (OPTIONS) ----------

async fn discovery() -> impl IntoResponse {
    (
        StatusCode::NO_CONTENT,
        [
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Tus-Version", TUS_VERSION.to_string()),
            ("Tus-Extension", "creation,termination".to_string()),
            ("Tus-Max-Size", TUS_MAX_SIZE.to_string()),
        ],
    )
}

// ---------- POST /tus/uploads (Creation) ----------

/// Decodes tus `Upload-Metadata`: comma-separated `key base64(value)` pairs.
///
/// `pub` uniquement pour que la cible de fuzzing (`fuzz/fuzz_targets/`) puisse
/// l'atteindre : une cible libFuzzer est une caisse SEPAREE, qui ne voit que
/// l'API publique de celle-ci. Reste un detail d'implementation de tus, a ne
/// pas appeler ailleurs.
pub fn parse_metadata(raw: &str) -> std::collections::HashMap<String, String> {
    use base64::Engine;
    raw.split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, ' ');
            let key = parts.next().unwrap_or("").to_string();
            let value = parts.next().unwrap_or("");
            let bytes = base64::engine::general_purpose::STANDARD.decode(value).ok()?;
            let s = String::from_utf8(bytes).ok()?;
            Some((key, s))
        })
        .collect()
}

async fn create_upload(
    State(state): State<AppState>,
    ctx: TokenCtx,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiErr> {
    let total_size: i64 = headers
        .get("upload-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing Upload-Length"))?;
    if total_size < 0 || total_size > TUS_MAX_SIZE {
        return Err((StatusCode::BAD_REQUEST, "invalid Upload-Length"));
    }

    let raw_metadata = headers
        .get("upload-metadata")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let meta = parse_metadata(&raw_metadata);
    let name = meta.get("filename").cloned().unwrap_or_else(|| "upload.bin".to_string());
    let folder_id: Option<i64> = meta.get("folder_id").and_then(|v| v.parse().ok());
    let expected_base_version: Option<i64> = meta.get("expected_base_version").and_then(|v| v.parse().ok());

    if ctx.used_bytes + total_size > ctx.quota_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "quota exceeded"));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().to_rfc3339();

    tokio::fs::create_dir_all(partial_dir())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "io error"))?;
    tokio::fs::File::create(partial_path(&id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "io error"))?;

    state
        .db
        .execute(
            "INSERT INTO tus_uploads (id, owner_token_id, folder_id, name, total_size, uploaded_bytes, metadata, created_at, completed, expected_base_version) \
             VALUES ($1, $2, $3, $4, $5, 0, $6, $7, 0, $8)",
            params!(&id, ctx.id, folder_id, &name, total_size, &raw_metadata, created_at, expected_base_version),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok((
        StatusCode::CREATED,
        [
            ("Location", format!("/tus/uploads/{id}")),
            ("Tus-Resumable", TUS_VERSION.to_string()),
        ],
    ))
}

// ---------- HEAD /tus/uploads/{id} ----------

async fn head_upload(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiErr> {
    let upload = get_owned_upload(&state, &ctx, &id).await?;
    Ok((
        StatusCode::OK,
        [
            ("Upload-Offset", upload.uploaded_bytes.to_string()),
            ("Upload-Length", upload.total_size.to_string()),
            ("Tus-Resumable", TUS_VERSION.to_string()),
            ("Cache-Control", "no-store".to_string()),
        ],
    ))
}

// ---------- PATCH /tus/uploads/{id} (Core) ----------

async fn patch_upload(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiErr> {
    let upload = get_owned_upload(&state, &ctx, &id).await?;
    if upload.completed != 0 {
        return Err((StatusCode::CONFLICT, "upload already completed"));
    }

    let offset: i64 = headers
        .get("upload-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing Upload-Offset"))?;
    if offset != upload.uploaded_bytes {
        return Err((StatusCode::CONFLICT, "Upload-Offset mismatch"));
    }

    let new_offset = offset + body.len() as i64;
    if new_offset > upload.total_size {
        return Err((StatusCode::BAD_REQUEST, "upload exceeds declared Upload-Length"));
    }

    {
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(partial_path(&id))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "io error"))?;
        f.write_all(&body).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "io error"))?;
        f.flush().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "io error"))?;
    }

    state
        .db
        .execute(
            "UPDATE tus_uploads SET uploaded_bytes = $1 WHERE id = $2",
            params!(new_offset, &id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let mut headers = HeaderMap::new();
    headers.insert("upload-offset", new_offset.to_string().parse().unwrap());
    headers.insert("tus-resumable", TUS_VERSION.parse().unwrap());
    if new_offset == upload.total_size {
        // DETACHE dans une tache, et pas simplement `.await` ici : axum abandonne
        // le futur du handler des que le client se deconnecte, ce qui interrompait
        // la finalisation EN COURS DE ROUTE.
        //
        // Constate en prod le 02/09/2026 sur un fichier de 1,05 Go : les
        // 1 132 793 393 octets etaient tous arrives (`uploaded_bytes` =
        // `total_size`), des chunks etaient deja ecrits, mais le
        // `UPDATE ... completed = 1` plus bas n'etait jamais atteint. Le client
        // (undici, cote OxaDash) abandonne au bout de 300 s alors que decouper et
        // chiffrer 1 Go prend davantage — donc l'envoi restait a `completed = 0`
        // et le fichier s'affichait a 0 octet.
        //
        // `tokio::spawn` rend le travail non annulable par le client : la reponse
        // peut etre perdue, la version est quand meme creee, et un HEAD ultérieur
        // (ou une reprise) voit un envoi termine.
        let etat = state.clone();
        let jeton = ctx.id;
        let identifiant = id.clone();
        let nom = upload.name.clone();
        let dossier = upload.folder_id;
        let base = upload.expected_base_version;
        let outcome = tokio::spawn(async move {
            finish_upload(&etat, jeton, &identifiant, &nom, dossier, base).await
        })
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "finalisation interrompue"))??;
        if let crate::files::StoreOutcome::Conflict { conflicted_copy_file_id, conflicted_copy_name, .. } = outcome {
            headers.insert("x-conflict", "true".parse().unwrap());
            headers.insert("x-conflicted-copy-file-id", conflicted_copy_file_id.to_string().parse().unwrap());
            if let Ok(v) = axum::http::HeaderValue::from_str(&conflicted_copy_name) {
                headers.insert("x-conflicted-copy-name", v);
            }
        }
    }

    Ok((StatusCode::NO_CONTENT, headers))
}

/// Assembles the completed partial file through the normal chunking+versioning pipeline,
/// sharing `files::store_new_version` (chunk-refcount upsert + file_versions insert +
/// `current_version_id` update) with the regular upload/office-save paths.
/// Prend `owner_token_id` et non un `&TokenCtx` : seul l'identifiant du jeton
/// servait, et la reprise au demarrage n'a pas de contexte de requete a fournir.
async fn finish_upload(
    state: &AppState,
    owner_token_id: i64,
    id: &str,
    name: &str,
    folder_id: Option<i64>,
    expected_base_version: Option<i64>,
) -> Result<crate::files::StoreOutcome, ApiErr> {
    // On ne LIT PAS le fichier partiel en memoire : il fait la taille de l'envoi,
    // soit plusieurs gigaoctets. Le decoupage se fait en flux depuis le disque.
    let chemin_partiel = partial_path(id);

    let existing_file: Option<IdRow> = match folder_id {
        Some(fid) => {
            state
                .db
                .query_map_optional(
                    "SELECT id FROM files WHERE name = $1 AND folder_id = $2 AND owner_token_id = $3 AND deleted_at IS NULL",
                    params!(name, fid, owner_token_id),
                )
                .await
        }
        None => {
            state
                .db
                .query_map_optional(
                    "SELECT id FROM files WHERE name = $1 AND folder_id IS NULL AND owner_token_id = $2 AND deleted_at IS NULL",
                    params!(name, owner_token_id),
                )
                .await
        }
    }
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let created_at = chrono::Utc::now().to_rfc3339();

    let file_id = if let Some(f) = existing_file {
        f.id
    } else {
        let row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO files (folder_id, name, owner_token_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(folder_id, name, owner_token_id, created_at.clone()),
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        row.id
    };

    let outcome = crate::files::store_new_version_from_path(
        state, file_id, &chemin_partiel, expected_base_version, owner_token_id,
    ).await?;
    let size = match &outcome {
        crate::files::StoreOutcome::Normal { size, .. } | crate::files::StoreOutcome::Conflict { size, .. } => *size,
    };

    state
        .db
        .execute(
            "UPDATE tokens SET used_bytes = used_bytes + $1 WHERE id = $2",
            params!(size, owner_token_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    state
        .db
        .execute("UPDATE tus_uploads SET completed = 1 WHERE id = $1", params!(id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let _ = tokio::fs::remove_file(partial_path(id)).await;

    if !matches!(outcome, crate::files::StoreOutcome::Conflict { .. }) {
        crate::audit::log(&state.db, owner_token_id, "file.upload.tus", Some("file"), Some(file_id), None).await;
    }

    Ok(outcome)
}

/// Reprend les envois entierement recus mais jamais assembles.
///
/// POURQUOI. Un envoi tus vit en deux temps : les tranches remplissent un
/// fichier partiel, puis la derniere declenche l'assemblage (decoupage,
/// chiffrement, creation de la version). Entre les deux il existe une fenetre ou
/// `uploaded_bytes == total_size` mais `completed == 0` : tous les octets du
/// client sont sur le disque, et rien ne les represente encore.
///
/// Si le service s'arrete dans cette fenetre — redemarrage, deploiement, plantage
/// — personne ne reprend le travail. Le client a envoye son fichier, l'a vu
/// atteindre 100 %, et voit un fichier a 0 octet. Constate en prod le 02/09/2026
/// sur 1,05 Go.
///
/// On rejoue donc ces envois au demarrage et periodiquement. C'est idempotent :
/// `finish_upload` remet `completed = 1` et supprime le fichier partiel, donc un
/// envoi deja repris ne ressort pas de la requete.
pub async fn reprendre_envois_inacheves(state: &AppState) {
    let en_attente: Vec<UploadRow> = match state
        .db
        .query_map(
            "SELECT id, owner_token_id, folder_id, name, total_size, uploaded_bytes, completed, \
             expected_base_version FROM tus_uploads \
             WHERE completed = 0 AND uploaded_bytes > 0 AND uploaded_bytes = total_size",
            params!(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("reprise des envois tus impossible : {e}");
            return;
        }
    };

    if en_attente.is_empty() {
        return;
    }
    tracing::info!("reprise de {} envoi(s) tus recu(s) mais non assemble(s)", en_attente.len());

    for envoi in en_attente {
        // Le fichier partiel est la seule source des octets : sans lui, l'envoi
        // n'est pas reprenable et le rejouer ecrirait un fichier tronque.
        let chemin = partial_path(&envoi.id);
        match tokio::fs::metadata(&chemin).await {
            Ok(m) if m.len() as i64 == envoi.total_size => {}
            Ok(m) => {
                tracing::warn!(
                    "envoi {} ignore : le fichier partiel fait {} octets pour {} attendus",
                    envoi.id, m.len(), envoi.total_size
                );
                continue;
            }
            Err(_) => {
                tracing::warn!("envoi {} ignore : fichier partiel absent", envoi.id);
                continue;
            }
        }

        match finish_upload(
            state,
            envoi.owner_token_id,
            &envoi.id,
            &envoi.name,
            envoi.folder_id,
            envoi.expected_base_version,
        )
        .await
        {
            Ok(_) => tracing::info!("envoi {} assemble ({} octets)", envoi.id, envoi.total_size),
            Err((_, msg)) => tracing::error!("assemblage de l'envoi {} echoue : {msg}", envoi.id),
        }
    }
}

// ---------- DELETE /tus/uploads/{id} (Termination) ----------

async fn delete_upload(
    State(state): State<AppState>,
    ctx: TokenCtx,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiErr> {
    let _upload = get_owned_upload(&state, &ctx, &id).await?;
    let _ = tokio::fs::remove_file(partial_path(&id)).await;
    state
        .db
        .execute("DELETE FROM tus_uploads WHERE id = $1", params!(&id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    Ok((StatusCode::NO_CONTENT, tus_headers()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("PLASTE_DATA_DIR", dir.path().to_string_lossy().to_string());
        }
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        init_schema(&db).await;
        let created_at = chrono::Utc::now().to_rfc3339();
        db.execute(
            "INSERT INTO tokens (token, owner, is_admin, quota_bytes, created_at) VALUES ('test-token', 'test', 0, 999999999, $1)",
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
        // leak tempdir so the db/partial files survive for the test's lifetime
        std::mem::forget(dir);
        state
    }

    fn auth_req(method: &str, uri: &str, _body: Vec<u8>) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", "Bearer test-token")
    }

    #[tokio::test]
    async fn resumable_upload_full_flow() {
        let state = test_state().await;
        let app = router().with_state(state.clone());

        let total = 300_000usize;
        let chunk1 = vec![1u8; 100_000];
        let chunk2 = vec![2u8; 100_000];
        let chunk3 = vec![3u8; 100_000];
        let mut expected = Vec::with_capacity(total);
        expected.extend_from_slice(&chunk1);
        expected.extend_from_slice(&chunk2);
        expected.extend_from_slice(&chunk3);

        // (a) create
        let resp = app
            .clone()
            .oneshot(
                auth_req("POST", "/tus/uploads", vec![])
                    .header("upload-length", total.to_string())
                    .header("upload-metadata", "filename dXBsb2FkLmJpbg==")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let location = resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let upload_id = location.strip_prefix("/tus/uploads/").unwrap().to_string();

        // (b) first chunk at offset 0
        let resp = app
            .clone()
            .oneshot(
                auth_req("PATCH", &location, chunk1.clone())
                    .header("upload-offset", "0")
                    .header("content-type", "application/offset+octet-stream")
                    .body(Body::from(chunk1.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("upload-offset").unwrap(), "100000");

        // (c) resumed chunk at offset 100000
        let resp = app
            .clone()
            .oneshot(
                auth_req("PATCH", &location, chunk2.clone())
                    .header("upload-offset", "100000")
                    .header("content-type", "application/offset+octet-stream")
                    .body(Body::from(chunk2.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("upload-offset").unwrap(), "200000");

        // (d) final chunk at offset 200000 completes the upload
        let resp = app
            .clone()
            .oneshot(
                auth_req("PATCH", &location, chunk3.clone())
                    .header("upload-offset", "200000")
                    .header("content-type", "application/offset+octet-stream")
                    .body(Body::from(chunk3.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("upload-offset").unwrap(), "300000");

        let row: UploadRow = state
            .db
            .query_map_optional(
                "SELECT id, owner_token_id, folder_id, name, total_size, uploaded_bytes, completed, expected_base_version FROM tus_uploads WHERE id = $1",
                params!(&upload_id),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.completed, 1);
        assert_eq!(row.total_size, total as i64);

        struct VRow {
            manifest: String,
            size: i64,
        }
        impl From<&mut hiqlite::Row<'_>> for VRow {
            fn from(r: &mut hiqlite::Row<'_>) -> Self {
                Self { manifest: r.get("manifest"), size: r.get("size") }
            }
        }
        let v: VRow = (&mut state
            .db
            .query_raw_one(
                "SELECT fv.manifest AS manifest, fv.size AS size FROM file_versions fv \
                 JOIN files f ON f.current_version_id = fv.id WHERE f.name = 'upload.bin'",
                params!(),
            )
            .await
            .unwrap())
            .into();
        assert_eq!(v.size, total as i64);
        let manifest: Vec<String> = serde_json::from_str(&v.manifest).unwrap();
        let read_back = state.storage.read_manifest(&manifest).await.unwrap();
        assert_eq!(read_back, expected);

        assert!(!partial_path(&upload_id).exists());
    }

    /// Completes a single-chunk tus upload of `data` for `name`, optionally with an
    /// `expected_base_version` metadata key, and returns the final PATCH response.
    async fn tus_upload_once(
        app: &axum::Router,
        name: &str,
        data: &[u8],
        expected_base_version: Option<i64>,
    ) -> axum::http::Response<Body> {
        use base64::Engine;
        let filename_b64 = base64::engine::general_purpose::STANDARD.encode(name);
        let mut metadata = format!("filename {filename_b64}");
        if let Some(v) = expected_base_version {
            let v_b64 = base64::engine::general_purpose::STANDARD.encode(v.to_string());
            metadata.push_str(&format!(",expected_base_version {v_b64}"));
        }

        let resp = app
            .clone()
            .oneshot(
                auth_req("POST", "/tus/uploads", vec![])
                    .header("upload-length", data.len().to_string())
                    .header("upload-metadata", metadata)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();

        app.clone()
            .oneshot(
                auth_req("PATCH", &location, data.to_vec())
                    .header("upload-offset", "0")
                    .header("content-type", "application/offset+octet-stream")
                    .body(Body::from(data.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn tus_stale_expected_base_version_creates_conflicted_copy() {
        let state = test_state().await;
        crate::audit::init_schema(&state.db).await;
        let app = router().with_state(state.clone());

        // v1
        let resp = tus_upload_once(&app, "doc.txt", b"content-v1", None).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(resp.headers().get("x-conflict").is_none());

        // "Client A" bumps to v2 based on v1.
        let resp = tus_upload_once(&app, "doc.txt", b"content-v2-clientA", Some(1)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(resp.headers().get("x-conflict").is_none());

        // "Client B" also thought base was v1: conflict.
        let resp = tus_upload_once(&app, "doc.txt", b"content-v2-clientB", Some(1)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("x-conflict").unwrap(), "true");
        let conflicted_id: i64 = resp
            .headers()
            .get("x-conflicted-copy-file-id")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();

        struct FRow {
            manifest: String,
        }
        impl From<&mut hiqlite::Row<'_>> for FRow {
            fn from(r: &mut hiqlite::Row<'_>) -> Self {
                Self { manifest: r.get("manifest") }
            }
        }

        // Original file (name "doc.txt") is untouched at v2 content.
        let orig: FRow = (&mut state
            .db
            .query_raw_one(
                "SELECT fv.manifest AS manifest FROM file_versions fv \
                 JOIN files f ON f.current_version_id = fv.id WHERE f.name = 'doc.txt'",
                params!(),
            )
            .await
            .unwrap())
            .into();
        let manifest: Vec<String> = serde_json::from_str(&orig.manifest).unwrap();
        let data = state.storage.read_manifest(&manifest).await.unwrap();
        assert_eq!(data, b"content-v2-clientA");

        // Conflicted copy has client B's content.
        let copy: FRow = (&mut state
            .db
            .query_raw_one(
                "SELECT fv.manifest AS manifest FROM file_versions fv \
                 JOIN files f ON f.current_version_id = fv.id WHERE f.id = $1",
                params!(conflicted_id),
            )
            .await
            .unwrap())
            .into();
        let manifest: Vec<String> = serde_json::from_str(&copy.manifest).unwrap();
        let data = state.storage.read_manifest(&manifest).await.unwrap();
        assert_eq!(data, b"content-v2-clientB");
    }

    #[tokio::test]
    async fn conflicting_offset_returns_409() {
        let state = test_state().await;
        let app = router().with_state(state);

        let resp = app
            .clone()
            .oneshot(
                auth_req("POST", "/tus/uploads", vec![])
                    .header("upload-length", "1000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp = app
            .oneshot(
                auth_req("PATCH", &location, vec![0u8; 10])
                    .header("upload-offset", "50")
                    .header("content-type", "application/offset+octet-stream")
                    .body(Body::from(vec![0u8; 10]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}

#[cfg(test)]
mod proprietes_metadonnees {
    use super::parse_metadata;
    use base64::Engine;
    use proptest::prelude::*;

    // `Upload-Metadata` arrive d'Internet, en clair, dans un en-tete HTTP. Ces
    // proprietes ne verifient pas un cas particulier mais un invariant sur
    // TOUTE entree : le decodage ne doit jamais paniquer, et ne jamais rendre
    // une valeur qui n'a pas ete effectivement decodee depuis du base64.
    proptest! {
        /// Aucune entree, meme absurde, ne doit faire paniquer le decodage.
        /// Une panique ici serait un deni de service : un en-tete suffirait a
        /// tuer le gestionnaire de requete.
        #[test]
        fn ne_panique_jamais(brut in ".{0,400}") {
            let _ = parse_metadata(&brut);
        }

        /// Une paire bien formee doit etre restituee telle quelle. C'est la
        /// contrepartie de la propriete precedente : ne pas paniquer ne sert a
        /// rien si le decodage perd des donnees valides.
        #[test]
        fn restitue_une_paire_bien_formee(
            cle in "[a-zA-Z][a-zA-Z0-9_]{0,20}",
            valeur in ".{0,60}",
        ) {
            let encode = base64::engine::general_purpose::STANDARD.encode(valeur.as_bytes());
            let sortie = parse_metadata(&format!("{cle} {encode}"));
            prop_assert_eq!(sortie.get(&cle), Some(&valeur));
        }

        /// Une valeur non decodable doit etre ECARTEE, pas transmise brute.
        /// Sans ca, `filename` pourrait contenir n'importe quoi et ce nom part
        /// ensuite en base puis dans du HTML.
        #[test]
        fn ecarte_une_valeur_non_base64(cle in "[a-z]{1,10}") {
            // `!` et `@` ne font pas partie de l'alphabet base64 standard.
            let sortie = parse_metadata(&format!("{cle} !!!@@@"));
            prop_assert!(sortie.get(&cle).is_none());
        }

        /// Le separateur de paires est la virgule : aucune cle rendue ne doit en
        /// contenir, sinon une seule paire pourrait en simuler plusieurs.
        #[test]
        fn aucune_cle_ne_contient_de_virgule(brut in "[a-zA-Z0-9 ,=+/]{0,200}") {
            for cle in parse_metadata(&brut).keys() {
                prop_assert!(!cle.contains(','), "cle inattendue : {:?}", cle);
            }
        }
    }
}
