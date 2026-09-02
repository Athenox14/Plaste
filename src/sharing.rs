//! Sharing: public links to a file or folder (optionally password-protected and/or expiring),
//! plus per-token/per-group `permissions` grants for authenticated users.
//!
//! The `/public/shares/*` routes are the only unauthenticated routes in the service, so the
//! reasoning behind the link token, the password hashing, the brute-force budget and the
//! headers used to serve user-uploaded bytes is documented inline below.

use std::sync::LazyLock;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
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

pub(crate) type ApiErr = (StatusCode, &'static str);

// ---------- link tokens, passwords, brute-force budget ----------

/// Every column of `shares`, so the row mapper and the places that load a share can't drift
/// apart as columns get added.
const SHARE_COLUMNS: &str = "id, resource_type, resource_id, owner_token_id, share_token, \
     password_hash, expires_at, permission, created_at, view_count, download_count, last_access_at";

/// Random bytes behind a share link token: 16 bytes = 128 bits, base64url-encoded to 22 chars.
///
/// Security: the bytes come from `Key::<Aes256Gcm>::generate()`, i.e. the same OS CSPRNG the
/// at-rest encryption keys use — not a sequential id, not a UUID. A guessable link is the whole
/// attack surface of an unauthenticated route, and a UUIDv4 both spends bits on fixed
/// version/variant nibbles (122 bits of real entropy) and advertises its own format, while a v1
/// would leak a timestamp and MAC address. This token is pure randomness: it encodes nothing
/// about the file, its owner, or when it was made, so holding one link reveals no pattern that
/// helps guess another.
const SHARE_TOKEN_BYTES: usize = 16;

fn generate_share_token() -> String {
    use aes_gcm::aead::{Generate, Key};
    let bytes: [u8; 32] = Key::<aes_gcm::Aes256Gcm>::generate().into();
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bytes[..SHARE_TOKEN_BYTES],
    )
}

/// Hashes a share password with Argon2id (default params: 19 MiB, 2 passes), random per-hash
/// salt, stored in PHC string format.
///
/// Security: a bare digest is fatally fast here — a GPU tries billions of candidates a second,
/// and link passwords are short human-chosen ones. Argon2 is deliberately slow *and*
/// memory-hard, so cracking a leaked `shares` table costs real money per guess. The per-hash
/// salt means two shares protected by the same password get different hashes, so the table
/// can't be swept with one precomputed dictionary.
fn hash_password(password: &str) -> Result<String, ApiErr> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "password hash failed"))
}

/// Verifies a candidate password against a stored PHC hash.
///
/// Security: `verify_password` compares the derived key in constant time internally (via
/// `password_hash`'s `subtle`-backed `Output` equality), so a wrong password is rejected in the
/// same time regardless of how many leading bytes matched. A naive `==` on digests would let an
/// attacker reconstruct the expected value byte-by-byte from response timings.
fn verify_password(stored_phc: &str, candidate: Option<&str>) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    let Ok(parsed) = PasswordHash::new(stored_phc) else {
        // Unparseable hash = fail closed rather than fall back to a weaker comparison.
        return false;
    };
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}

/// Name of the header a public caller supplies a share password in.
///
/// Security: the password is NEVER accepted from the query string. A URL is written to the
/// reverse proxy access log, the browser history and address bar, and leaks in `Referer` on any
/// outbound navigation -- i.e. it would be persisted in exactly the places a secret must not
/// be. A request header appears in none of those. There is deliberately no `?password=`
/// fallback: leaving the dangerous path in "for compatibility" would keep the vulnerability.
pub const PASSWORD_HEADER: &str = "x-share-password";

fn header_password(headers: &HeaderMap) -> Option<&str> {
    headers.get(PASSWORD_HEADER)?.to_str().ok()
}

/// How long a download ticket stays valid. Long enough to click the button on the share page,
/// far too short to be worth anything to someone reading a log file later.
const TICKET_TTL_SECS: u64 = 120;

/// Domain-separation context for the ticket signing subkey (see `KeyRing::derive_subkey`).
const TICKET_KEY_CONTEXT: &str = "plaste share download ticket v1";

/// The key download tickets are signed with, derived from the existing master key
/// (`PLASTE_DATA_DIR/master_keys.json`) -- no new secret, no new config, and stable across
/// restarts because that key is persisted. It is not the master key itself: BLAKE3's KDF
/// yields a subkey that cannot decrypt anything.
///
/// A master-key rotation changes the subkey and so invalidates outstanding tickets; worst case
/// is a share page loaded less than TICKET_TTL_SECS before the rotation whose download button
/// returns 401 and has to be re-submitted.
fn ticket_key(state: &AppState) -> [u8; 32] {
    state.storage.derive_subkey(TICKET_KEY_CONTEXT)
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ticket_signature(key: &[u8; 32], share_token: &str, expires_at: u64) -> blake3::Hash {
    // `share_token` is fixed-length base64url and never contains '.', so "token.exp" is an
    // unambiguous encoding of the two fields.
    blake3::keyed_hash(key, format!("{share_token}.{expires_at}").as_bytes())
}

/// Mints a short-lived, stateless proof that this share's password was verified just now.
///
/// Why a ticket at all: the download link is a plain `GET` the browser performs, so no header
/// can be attached to it, and putting the password back in the URL is the very bug being fixed.
/// A ticket in a URL is acceptable where a password is not: it expires after
/// `TICKET_TTL_SECS`, is bound to one share token, and reveals nothing about the password.
fn mint_download_ticket(key: &[u8; 32], share_token: &str) -> String {
    let expires_at = now_epoch_secs() + TICKET_TTL_SECS;
    let sig = ticket_signature(key, share_token, expires_at);
    let payload = format!(
        "{expires_at}.{}",
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sig.as_bytes()
        )
    );
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
}

/// Verifies a ticket: right share, right signature, not expired.
///
/// Security: the signature comparison goes through `blake3::Hash`'s constant-time `PartialEq`,
/// like `tokens_match`. The expiry is part of the signed message, so extending it forges the
/// signature. Binding the share token means a ticket minted for share A is useless on share B.
/// A ticket proves only "the password was right less than TICKET_TTL_SECS ago" -- the caller
/// still re-loads and re-validates the share row, so revocation is unaffected by it.
fn verify_download_ticket(key: &[u8; 32], share_token: &str, ticket: &str) -> bool {
    let Ok(raw) = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, ticket)
    else {
        return false;
    };
    let Ok(raw) = String::from_utf8(raw) else {
        return false;
    };
    let Some((exp, sig_b64)) = raw.split_once('.') else {
        return false;
    };
    let Ok(expires_at) = exp.parse::<u64>() else {
        return false;
    };
    if now_epoch_secs() > expires_at {
        return false;
    }
    let Ok(sig) = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_b64)
    else {
        return false;
    };
    let Ok(sig): Result<[u8; 32], _> = sig.try_into() else {
        return false;
    };
    ticket_signature(key, share_token, expires_at) == blake3::Hash::from(sig)
}

/// Mints a download ticket for `share_token` under this server's signing key. Called by
/// share_page.rs once a submitted password has been accepted, so the download link it renders
/// carries a ticket instead of the password.
pub(crate) fn download_ticket(state: &AppState, share_token: &str) -> String {
    mint_download_ticket(&ticket_key(state), share_token)
}

/// Constant-time equality for the link token itself.
///
/// Security: `blake3::Hash`'s `PartialEq` is documented as constant-time, so hashing both sides
/// and comparing hashes leaks nothing through timing — and needs no extra dependency. This
/// backstops the SQL `WHERE share_token = $1` lookup, whose own comparison happens inside
/// SQLite's B-tree and makes no timing guarantee.
fn tokens_match(a: &str, b: &str) -> bool {
    blake3::hash(a.as_bytes()) == blake3::hash(b.as_bytes())
}

/// Per-share-token throttle on password attempts: 5 immediately, then one more every 12s.
///
/// Security: without a rate limit, a password-protected link falls to online brute force in
/// minutes. Argon2 raises the cost of each attempt but not the attempt *rate*. Keyed on the
/// share token rather than the client IP, because rotating source addresses is the cheap part
/// of an attack and would otherwise reset the budget; the per-IP `ratelimit::general()` layer
/// in main.rs still applies on top.
///
/// ponytail: in-process state, so the budget is per replica — N replicas behind a load balancer
/// multiply the real attempt rate by N, and a restart clears it. Adequate for the single-node
/// deployment this runs on; move the counter into the hiqlite DB if it's ever scaled out.
static PASSWORD_ATTEMPTS: LazyLock<
    governor::RateLimiter<
        String,
        governor::state::keyed::DefaultKeyedStateStore<String>,
        governor::clock::DefaultClock,
    >,
> = LazyLock::new(|| {
    let quota = governor::Quota::with_period(std::time::Duration::from_secs(12))
        .expect("non-zero period")
        .allow_burst(std::num::NonZeroU32::new(5).expect("non-zero burst"));
    governor::RateLimiter::keyed(quota)
});

// ---------- shared row types ----------

// Fields are pub(crate): share_page.rs (human-readable landing page) reads a resolved share's
// resource_type/resource_id without duplicating the validation in load_valid_share below.
pub(crate) struct ShareRow {
    id: i64,
    pub(crate) resource_type: String,
    pub(crate) resource_id: i64,
    owner_token_id: i64,
    share_token: String,
    password_hash: Option<String>,
    expires_at: Option<String>,
    permission: String,
    created_at: String,
    view_count: i64,
    download_count: i64,
    last_access_at: Option<String>,
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
            view_count: row.get("view_count"),
            download_count: row.get("download_count"),
            last_access_at: row.get("last_access_at"),
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

    // Reject an expiry we can't parse rather than storing it and silently treating the share
    // as non-expiring: an owner who asked for an expiry must not get an eternal link.
    if let Some(expires_at) = &req.expires_at {
        if chrono::DateTime::parse_from_rfc3339(expires_at).is_err() {
            return Err((StatusCode::BAD_REQUEST, "expires_at must be an rfc3339 timestamp"));
        }
    }

    let share_token = generate_share_token();
    let password_hash = match req.password.as_deref() {
        Some(p) => Some(hash_password(p)?),
        None => None,
    };
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
    /// True/false only — never the hash itself, so `GET /shares` can't be used to farm
    /// material for an offline cracking run.
    password_protected: bool,
    view_count: i64,
    download_count: i64,
    last_access_at: Option<String>,
}

async fn list_shares(
    State(state): State<AppState>,
    ctx: TokenCtx,
) -> Result<Json<Vec<ShareResp>>, ApiErr> {
    let rows: Vec<ShareRow> = state
        .db
        .query_map(
            format!("SELECT {SHARE_COLUMNS} FROM shares WHERE owner_token_id = $1"),
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
                password_protected: s.password_hash.is_some(),
                view_count: s.view_count,
                download_count: s.download_count,
                last_access_at: s.last_access_at,
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
            format!("SELECT {SHARE_COLUMNS} FROM shares WHERE id = $1"),
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

/// The download route's only query parameter: a short-lived ticket (see
/// `mint_download_ticket`). There is deliberately no `password` field.
#[derive(Deserialize)]
struct DownloadQuery {
    t: Option<String>,
}

/// Returns true if `expires_at` (rfc3339, if present) is in the past. An unparseable stored
/// value counts as expired: fail closed, since the alternative is serving a link forever that
/// the owner asked to have an end date.
fn share_expired(expires_at: &Option<String>) -> bool {
    match expires_at.as_deref() {
        None => false,
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|expiry| expiry < chrono::Utc::now())
            .unwrap_or(true),
    }
}

/// Looks up a share by token and re-validates it in full. Shared by resolve + download.
///
/// Security: every gate is applied on EVERY public request, never cached and never taken on
/// trust from creation time. Revocation is a row `DELETE`, so a revoked link stops resolving
/// on the very next request; expiry is recomputed against the current clock; the password is
/// re-verified each time. There is no session or cookie handed out after a successful password
/// check, precisely so that revoking or expiring a share can't be outlived by a ticket issued
/// earlier. A download ticket is the single exception, and it stands in for the *password
/// check* only -- the row is still re-read and re-validated below, so no ticket can outlive a
/// revocation or an expiry.
pub(crate) async fn load_valid_share(
    state: &AppState,
    share_token: &str,
    password: Option<&str>,
) -> Result<ShareRow, ApiErr> {
    load_valid_share_inner(state, share_token, password, None).await
}

/// As `load_valid_share`, but a valid download ticket may satisfy the password gate.
async fn load_valid_share_inner(
    state: &AppState,
    share_token: &str,
    password: Option<&str>,
    ticket: Option<&str>,
) -> Result<ShareRow, ApiErr> {
    let share: Option<ShareRow> = state
        .db
        .query_map_optional(
            format!("SELECT {SHARE_COLUMNS} FROM shares WHERE share_token = $1"),
            params!(share_token),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let share = share.ok_or((StatusCode::NOT_FOUND, "share not found"))?;

    // Re-check the token in constant time. The SQL lookup already matched, so this only guards
    // against timing side channels in the B-tree comparison, not against a wrong row.
    if !tokens_match(&share.share_token, share_token) {
        return Err((StatusCode::NOT_FOUND, "share not found"));
    }

    if share_expired(&share.expires_at) {
        return Err((StatusCode::GONE, "share expired"));
    }

    if let Some(hash) = &share.password_hash {
        // A valid ticket short-circuits the password check and nothing else: revocation (the
        // row is gone) and expiry were already re-evaluated above, on this very request.
        if let Some(ticket) = ticket {
            if verify_download_ticket(&ticket_key(state), share_token, ticket) {
                return Ok(share);
            }
            return Err((StatusCode::UNAUTHORIZED, "invalid or expired download ticket"));
        }
        // Throttle BEFORE hashing: Argon2's memory hardness cuts both ways, and ~19 MiB per
        // attempt makes an unthrottled verify endpoint a memory-exhaustion lever as well as a
        // brute-force one.
        if PASSWORD_ATTEMPTS.check_key(&share_token.to_string()).is_err() {
            return Err((StatusCode::TOO_MANY_REQUESTS, "too many password attempts"));
        }
        if !verify_password(hash, password) {
            // One message for "missing" and "wrong" alike: telling an attacker which of the two
            // it was confirms the link exists and is protected, and buys them nothing legitimate.
            return Err((StatusCode::UNAUTHORIZED, "password required or incorrect"));
        }
    }

    Ok(share)
}

/// Bumps the aggregate counters for a share and stamps the access time.
///
/// Privacy: intentionally records only counts and the latest timestamp — no IP, no user agent,
/// no referrer, no per-visit rows. The owner's real question is "was this link used, and how
/// much", which counters answer; a visit log would build a browsing history of people who
/// deliberately have no account here, and would be a far worse thing to leak than the counters.
/// Failures are logged and swallowed: a statistics write must never break the download itself.
async fn record_access(state: &AppState, share_id: i64, column: &str) {
    // `column` is one of two hardcoded call-site literals below, never user input — no
    // interpolation of anything request-derived reaches this SQL.
    let sql = format!(
        "UPDATE shares SET {column} = {column} + 1, last_access_at = $1 WHERE id = $2"
    );
    if let Err(e) = state
        .db
        .execute(sql, params!(chrono::Utc::now().to_rfc3339(), share_id))
        .await
    {
        tracing::warn!("failed to record share access stats for share {share_id}: {e}");
    }
}

/// Metadata for a shared file, for rendering a preview page.
///
/// Security: deliberately name/size/type only. No `owner_token_id`, no file id, no folder path,
/// no internal chunk manifest, and no sibling listing — an unauthenticated caller learns exactly
/// what it needs to draw a download page and nothing that maps out the owner's storage.
#[derive(Serialize)]
struct PublicFileInfo {
    kind: &'static str,
    name: String,
    size: i64,
    /// Advisory type for the preview UI's icon/labelling. Note this is NOT what the download
    /// route serves as `Content-Type` — see `download_public_share`.
    content_type: String,
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
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiErr> {
    let share = load_valid_share(&state, &share_token, header_password(&headers)).await?;

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
        record_access(&state, share.id, "view_count").await;
        Ok(Json(PublicFileInfo {
            kind: "file",
            content_type: mime_guess::from_path(&info.name).first_or_octet_stream().to_string(),
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
        record_access(&state, share.id, "view_count").await;

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
    headers: HeaderMap,
    Query(q): Query<DownloadQuery>,
) -> Result<impl IntoResponse, ApiErr> {
    let share =
        load_valid_share_inner(&state, &share_token, header_password(&headers), q.t.as_deref())
            .await?;
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
        size: i64,
    }
    impl From<&mut hiqlite::Row<'_>> for ManifestRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self { manifest: row.get("manifest"), size: row.get("size") }
        }
    }
    let version: Option<ManifestRow> = state
        .db
        .query_map_optional(
            "SELECT manifest, size FROM file_versions WHERE id = $1",
            params!(version_id),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
    let version = version.ok_or((StatusCode::NOT_FOUND, "version not found"))?;

    // The manifest is a list of content-addressed chunk hashes. Note nothing from the request
    // reaches the filesystem: the share token selects a `shares` row, that row's resource_id
    // selects a `files` row, and the bytes are located by chunk hash through the storage
    // backend's own path mapping. There is no attacker-controlled path segment anywhere in
    // this chain, so `../` in a token or filename has nothing to traverse.
    let manifest: std::sync::Arc<Vec<String>> = std::sync::Arc::new(
        serde_json::from_str(&version.manifest)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "decode error"))?,
    );

    record_access(&state, share.id, "download_count").await;

    // Stream chunk-by-chunk rather than `read_manifest`-ing the whole file into a Vec: this
    // service stores large files, and buffering one in memory per concurrent download is how a
    // public endpoint turns into an OOM. Peak memory is now one decrypted chunk per transfer.
    let storage = state.storage.clone();
    let stream = futures_util::stream::unfold(0usize, move |i| {
        let storage = storage.clone();
        let manifest = manifest.clone();
        async move {
            if i >= manifest.len() {
                return None;
            }
            let item = storage
                .read_chunk(&manifest[i])
                .await
                .map(axum::body::Bytes::from);
            Some((item, i + 1))
        }
    });

    let headers = [
        // Security: always `application/octet-stream` + `attachment`, never the guessed MIME
        // type. A user can upload an .html (or .svg, or anything with inline scripting) and
        // hand out a public link to it; served as its real type from this origin it would run
        // as a stored XSS with the service's own domain, able to read anything same-origin.
        // Forcing a download makes an uploaded file inert. `nosniff` closes the matching hole
        // where a browser ignores the declared type and sniffs the content instead.
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (header::CONTENT_LENGTH, version.size.to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", sanitize_filename(&name)),
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
    ];

    Ok((headers, axum::body::Body::from_stream(stream)))
}

/// Strips the characters that would let a filename break out of the quoted-string it's
/// interpolated into, or inject an extra header: quotes, backslashes, CR/LF and other controls.
/// `pub` pour la cible de fuzzing (caisse separee, API publique seulement).
pub fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect();
    // A name that sanitized down to nothing still needs to produce a valid header.
    if cleaned.trim().is_empty() {
        "download".to_string()
    } else {
        cleaned
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // ---------- pure unit tests: token, password, expiry, filename ----------

    #[test]
    fn share_token_has_128_bits_of_entropy_and_is_unpredictable() {
        let a = generate_share_token();
        let b = generate_share_token();
        assert_ne!(a, b, "two generated tokens must not collide");

        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &a).unwrap();
        assert_eq!(decoded.len(), SHARE_TOKEN_BYTES, "128 bits of randomness");
        assert_eq!(a.len(), 22, "base64url of 16 bytes, unpadded");

        // Not a UUID, and URL-safe alphabet only — the token can never introduce a path segment.
        assert!(!a.contains('-') || !a.contains("-4"));
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn password_is_argon2_hashed_with_a_per_share_salt() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.starts_with("$argon2"), "must be Argon2, not a bare digest: {hash}");
        // A bare digest of the password must never appear in the stored value.
        assert!(!hash.contains(&blake3::hash(b"correct horse").to_hex().to_string()));

        // Same password, two shares -> different hashes, so one dictionary can't crack both.
        let other = hash_password("correct horse").unwrap();
        assert_ne!(hash, other, "salt must be per-hash");
    }

    #[test]
    fn password_verification_accepts_only_the_right_password() {
        let hash = hash_password("s3cret").unwrap();
        assert!(verify_password(&hash, Some("s3cret")));
        assert!(!verify_password(&hash, Some("s3crets")));
        assert!(!verify_password(&hash, Some("")));
        // A protected share must never open just because no password was supplied.
        assert!(!verify_password(&hash, None));
        // A corrupt stored hash fails closed rather than degrading to a weaker check.
        assert!(!verify_password("not-a-phc-string", Some("s3cret")));
    }

    #[test]
    fn tokens_match_only_for_identical_tokens() {
        let t = generate_share_token();
        assert!(tokens_match(&t, &t));
        assert!(!tokens_match(&t, &generate_share_token()));
        // A prefix must not match: the comparison covers the whole value.
        assert!(!tokens_match(&t, &t[..t.len() - 1]));
    }

    #[test]
    fn expiry_is_evaluated_against_the_current_clock() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        assert!(share_expired(&Some(past)));
        assert!(!share_expired(&Some(future)));
        assert!(!share_expired(&None), "no expiry set means never expires");
        // Fail closed: an unparseable stored value must not yield an eternal link.
        assert!(share_expired(&Some("garbage".to_string())));
    }

    #[test]
    fn filename_cannot_break_out_of_the_content_disposition_header() {
        assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
        assert_eq!(sanitize_filename("a\"b.txt"), "ab.txt");
        assert_eq!(
            sanitize_filename("x\r\nSet-Cookie: evil=1"),
            "xSet-Cookie: evil=1",
            "CR/LF must not survive into the header"
        );
        assert_eq!(sanitize_filename("\r\n"), "download", "must stay a valid header");
    }

    /// Builds a ticket with an arbitrary expiry, the way `mint_download_ticket` does — used to
    /// forge the cases a well-behaved server would never produce.
    fn ticket_with_expiry(key: &[u8; 32], share_token: &str, expires_at: u64) -> String {
        let sig = ticket_signature(key, share_token, expires_at);
        let payload = format!(
            "{expires_at}.{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                sig.as_bytes()
            )
        );
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
    }

    #[test]
    fn a_freshly_minted_ticket_verifies_and_carries_no_password() {
        let key = [7u8; 32];
        let token = generate_share_token();
        let ticket = mint_download_ticket(&key, &token);
        assert!(verify_download_ticket(&key, &token, &ticket));

        // base64url only, so it is safe to drop straight into a URL, and it cannot contain the
        // password it stands in for.
        assert!(ticket.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!ticket.contains("password"));
    }

    #[test]
    fn an_expired_ticket_is_refused() {
        let key = [7u8; 32];
        let token = generate_share_token();
        // One second past its expiry is already too late; the TTL is only a couple of minutes.
        let stale = ticket_with_expiry(&key, &token, now_epoch_secs() - 1);
        assert!(!verify_download_ticket(&key, &token, &stale));
        assert!(verify_download_ticket(
            &key,
            &token,
            &ticket_with_expiry(&key, &token, now_epoch_secs() + 5)
        ));
        assert_eq!(TICKET_TTL_SECS, 120, "tickets must stay short-lived");
    }

    #[test]
    fn a_forged_ticket_is_refused() {
        let key = [7u8; 32];
        let token = generate_share_token();
        let expires_at = now_epoch_secs() + TICKET_TTL_SECS;

        // Signed with a different key (an attacker who does not have the server secret).
        assert!(!verify_download_ticket(
            &key,
            &token,
            &ticket_with_expiry(&[8u8; 32], &token, expires_at)
        ));

        // Expiry pushed out while keeping a signature that covered the original one: the expiry
        // is part of the signed message, so this cannot verify.
        let ticket = mint_download_ticket(&key, &token);
        let raw = String::from_utf8(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &ticket)
                .unwrap(),
        )
        .unwrap();
        let sig_b64 = raw.split_once('.').unwrap().1;
        let extended = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            format!("{}.{sig_b64}", now_epoch_secs() + 86_400),
        );
        assert!(!verify_download_ticket(&key, &token, &extended));

        // Structural junk fails closed rather than panicking.
        for junk in ["", "!!!!", "Zm9v", "Zm9vLmJhcg"] {
            assert!(!verify_download_ticket(&key, &token, junk), "junk accepted: {junk}");
        }
    }

    /// The download route has no `password` query parameter any more: a URL carrying one is
    /// parsed as if it were absent, so nothing can resurrect the leaky path by accident.
    #[test]
    fn the_download_route_has_no_password_query_parameter() {
        let parse = |qs: &str| {
            let uri: axum::http::Uri = format!("http://x/d?{qs}").parse().unwrap();
            Query::<DownloadQuery>::try_from_uri(&uri).unwrap().0
        };
        assert!(parse("password=s3cret").t.is_none());
        assert_eq!(parse("t=abc&password=s3cret").t.as_deref(), Some("abc"));
    }

    #[test]
    fn a_ticket_for_another_share_is_refused() {
        let key = [7u8; 32];
        let mine = generate_share_token();
        let theirs = generate_share_token();
        let ticket = mint_download_ticket(&key, &mine);
        assert!(verify_download_ticket(&key, &mine, &ticket));
        assert!(
            !verify_download_ticket(&key, &theirs, &ticket),
            "a ticket must not be replayable against a different share"
        );
    }

    // ---------- end-to-end over the router ----------

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

    /// Inserts a token plus a file whose current version holds `content`. Returns
    /// (bearer token, file id).
    async fn seed_file(state: &AppState, content: &[u8]) -> (String, i64) {
        let now = chrono::Utc::now().to_rfc3339();
        let token = uuid::Uuid::new_v4().to_string();
        let token_row: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO tokens (token, owner, created_at) VALUES ($1, 'owner', $2) RETURNING id",
                params!(&token, &now),
            )
            .await
            .unwrap();
        let file: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO files (name, owner_token_id, created_at) VALUES ('secret plan.html', $1, $2) RETURNING id",
                params!(token_row.id, &now),
            )
            .await
            .unwrap();
        let (manifest, size) = state.storage.write(content).await.unwrap();
        let version: IdRow = state
            .db
            .execute_returning_map_one(
                "INSERT INTO file_versions (file_id, version_no, size, manifest, created_at) \
                 VALUES ($1, 1, $2, $3, $4) RETURNING id",
                params!(file.id, size, serde_json::to_string(&manifest).unwrap(), &now),
            )
            .await
            .unwrap();
        state
            .db
            .execute(
                "UPDATE files SET current_version_id = $1 WHERE id = $2",
                params!(version.id, file.id),
            )
            .await
            .unwrap();
        (token, file.id)
    }

    async fn create_share_via_api(
        state: &AppState,
        bearer: &str,
        body: serde_json::Value,
    ) -> serde_json::Value {
        let resp = router()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/shares")
                    .header("authorization", format!("Bearer {bearer}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn public_get(
        state: &AppState,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        public_get_pw(state, uri, None).await
    }

    /// `password` goes in the `X-Share-Password` header — the only way the public routes accept
    /// it. There is no query-string form to exercise.
    async fn public_get_pw(
        state: &AppState,
        uri: &str,
        password: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut req = Request::builder().uri(uri);
        if let Some(pw) = password {
            req = req.header(PASSWORD_HEADER, pw);
        }
        let resp = router()
            .with_state(state.clone())
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, headers, bytes.to_vec())
    }

    /// One DB-backed test rather than several: `db::init` binds fixed loopback ports for
    /// hiqlite's raft/api listeners, so parallel instances would fight over them.
    #[tokio::test]
    async fn public_share_lifecycle_is_enforced_on_every_request() {
        let (state, _dir) = setup().await;
        let content = b"<script>alert(1)</script>".repeat(100);
        let (bearer, file_id) = seed_file(&state, &content).await;

        // --- an open share resolves and downloads ---
        let share = create_share_via_api(
            &state,
            &bearer,
            serde_json::json!({
                "resource_type": "file",
                "resource_id": file_id,
                "permission": "read",
            }),
        )
        .await;
        let token = share["share_token"].as_str().unwrap().to_string();
        let share_id = share["id"].as_i64().unwrap();

        let (status, _, body) = public_get(&state, &format!("/public/shares/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["name"], "secret plan.html");
        assert_eq!(info["size"].as_i64().unwrap(), content.len() as i64);
        // Public metadata must not leak who owns it or where it lives internally.
        for leaked in ["owner_token_id", "resource_id", "id", "manifest", "owner"] {
            assert!(info.get(leaked).is_none(), "public info leaked {leaked}");
        }

        let (status, headers, body) =
            public_get(&state, &format!("/public/shares/{token}/download")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, content, "streamed body must reassemble the whole file");
        // Uploaded HTML must be served inert, never as text/html on this origin.
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "application/octet-stream");
        assert_eq!(headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert!(headers
            .get(header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("attachment;"));

        // --- stats aggregated for the owner: 1 view, 1 download, a last-access stamp ---
        let resp = router()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/shares")
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let listed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(listed[0]["view_count"], 1);
        assert_eq!(listed[0]["download_count"], 1);
        assert!(listed[0]["last_access_at"].is_string());
        assert_eq!(listed[0]["password_protected"], false);

        // --- revoked share is refused immediately, on the very next request ---
        let resp = router()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/shares/{share_id}"))
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let (status, _, _) = public_get(&state, &format!("/public/shares/{token}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "revoked link must stop working");
        let (status, _, _) =
            public_get(&state, &format!("/public/shares/{token}/download")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "revoked link must not download either");

        // --- an already-expired share is refused (checked at access, not creation) ---
        let expired = create_share_via_api(
            &state,
            &bearer,
            serde_json::json!({
                "resource_type": "file",
                "resource_id": file_id,
                "permission": "read",
                "expires_at": (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
            }),
        )
        .await;
        let expired_token = expired["share_token"].as_str().unwrap();
        let (status, _, _) = public_get(&state, &format!("/public/shares/{expired_token}")).await;
        assert_eq!(status, StatusCode::GONE);
        let (status, _, _) =
            public_get(&state, &format!("/public/shares/{expired_token}/download")).await;
        assert_eq!(status, StatusCode::GONE);

        // --- a password-protected share demands the right password on both routes ---
        let protected = create_share_via_api(
            &state,
            &bearer,
            serde_json::json!({
                "resource_type": "file",
                "resource_id": file_id,
                "permission": "read",
                "password": "open sesame",
            }),
        )
        .await;
        let pt = protected["share_token"].as_str().unwrap();

        let (status, _, _) = public_get(&state, &format!("/public/shares/{pt}")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no password supplied");
        let (status, _, _) =
            public_get_pw(&state, &format!("/public/shares/{pt}"), Some("wrong")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) =
            public_get_pw(&state, &format!("/public/shares/{pt}/download"), Some("wrong")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "download must be gated too");

        let (status, _, _) =
            public_get_pw(&state, &format!("/public/shares/{pt}"), Some("open sesame")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, body) =
            public_get_pw(&state, &format!("/public/shares/{pt}/download"), Some("open sesame"))
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, content);

        // --- the download ticket the share page hands out works, and only there ---
        let ticket = download_ticket(&state, pt);
        let (status, _, body) =
            public_get(&state, &format!("/public/shares/{pt}/download?t={ticket}")).await;
        assert_eq!(status, StatusCode::OK, "a fresh ticket must be accepted");
        assert_eq!(body, content);

        let (status, _, _) =
            public_get(&state, &format!("/public/shares/{pt}/download?t=deadbeef")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "a garbage ticket must be refused");

        // The ticket is bound to one share: the open share's token can't reuse it, and this
        // one's can't be swapped for another protected share's.
        let other = create_share_via_api(
            &state,
            &bearer,
            serde_json::json!({
                "resource_type": "file",
                "resource_id": file_id,
                "permission": "read",
                "password": "open sesame",
            }),
        )
        .await;
        let other_token = other["share_token"].as_str().unwrap();
        let (status, _, _) =
            public_get(&state, &format!("/public/shares/{other_token}/download?t={ticket}")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "a ticket for another share must be refused");

        // --- brute force runs out of budget rather than continuing indefinitely; a POST-style
        // header submission is throttled exactly like the old query-string one was ---
        let mut saw_429 = false;
        for _ in 0..12 {
            let (status, _, _) =
                public_get_pw(&state, &format!("/public/shares/{pt}"), Some("nope")).await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "password attempts must be rate limited");

        // --- a ticket must not outlive revocation ---
        let fresh = download_ticket(&state, other_token);
        let other_id = other["id"].as_i64().unwrap();
        let resp = router()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/shares/{other_id}"))
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let (status, _, _) =
            public_get(&state, &format!("/public/shares/{other_token}/download?t={fresh}")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a ticket must never survive a revocation"
        );
    }
}
