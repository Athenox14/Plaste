//! Connexion KonnectID (SSO) pour Plaste.
//!
//! Plaste ne s'authentifiait que par `Authorization: Bearer <jeton>`. C'est
//! correct pour une API, mais impose a l'utilisateur de copier un secret a la
//! main — et c'est precisement ce secret qu'on lui demande de garder au chaud
//! (voir la rotation dans `admin.rs`). Il peut desormais se connecter avec son
//! compte KonnectID, et le serveur retrouve son jeton tout seul.
//!
//! CE QUI N'EST **PAS** UN OIDC STANDARD : KonnectID expose l'echange de code
//! et le userinfo derriere des routes tRPC (`/api/trpc/oauth2.token`,
//! `/api/trpc/oauth2.userInfo`), avec un corps PLAT a l'aller et une reponse
//! enveloppee dans `result.data` (parfois `result.data.json`) au retour. Une
//! bibliotheque OIDC generique ne fonctionne pas ici ; on reproduit exactement
//! ce que fait OxaDash (`server/utils/konnect.ts`), seul contrat connu.
//!
//! RAPPROCHEMENT DES IDENTITES : `tokens.owner` contient l'email — c'est ce
//! qu'OxaDash y ecrit a la creation du compte. On associe donc l'email
//! KonnectID a ce champ. Aucun compte n'est CREE par ce chemin : se connecter
//! ne doit pas provisionner de stockage a l'insu de l'exploitant.

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use base64::Engine;
use hiqlite::params;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::AppState;

/// Duree de vie d'une session. Volontairement courte au regard d'un jeton
/// d'API : une session vit dans un navigateur, pas dans un fichier de config.
const SESSION_DAYS: i64 = 7;
/// Au-dela, un `state` en attente est considere comme abandonne. Couvre
/// largement un aller-retour de connexion, meme avec double authentification.
const STATE_MINUTES: i64 = 15;

pub const SESSION_COOKIE: &str = "plaste_session";

struct Config {
    base_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scope: String,
}

impl Config {
    /// `None` si la configuration est absente : le SSO est alors simplement
    /// desactive, et l'authentification par jeton continue de fonctionner.
    fn from_env() -> Option<Self> {
        Some(Self {
            base_url: std::env::var("PLASTE_KONNECT_BASE_URL")
                .unwrap_or_else(|_| "https://konnectid.me".to_string()),
            client_id: std::env::var("PLASTE_KONNECT_CLIENT_ID").ok()?,
            client_secret: std::env::var("PLASTE_KONNECT_CLIENT_SECRET").ok()?,
            redirect_uri: std::env::var("PLASTE_KONNECT_REDIRECT_URI").ok()?,
            scope: std::env::var("PLASTE_KONNECT_SCOPE")
                .unwrap_or_else(|_| "openid required:email".to_string()),
        })
    }
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Verificateur PKCE : 32 octets aleatoires, encodes en base64url.
fn nouveau_verifier() -> String {
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    let mut brut = [0u8; 32];
    brut[..16].copy_from_slice(a.as_bytes());
    brut[16..].copy_from_slice(b.as_bytes());
    b64url(&brut)
}

fn defi_s256(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

fn erreur(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

#[derive(Deserialize)]
struct LoginQuery {
    /// Ou renvoyer le navigateur une fois connecte. Absent = on rend le jeton
    /// de session en JSON, ce dont un client lourd a besoin.
    redirect: Option<String>,
}

/// Demarre la connexion : cree un `state` + verificateur PKCE, les persiste, et
/// renvoie l'utilisateur chez KonnectID.
async fn login(State(state): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    let Some(cfg) = Config::from_env() else {
        return erreur(StatusCode::NOT_IMPLEMENTED, "SSO KonnectID non configure");
    };

    let etat = uuid::Uuid::new_v4().to_string();
    let verifier = nouveau_verifier();
    let defi = defi_s256(&verifier);

    // Le verificateur DOIT survivre a la redirection : le stocker en memoire
    // casserait des qu'il y a plus d'un processus ou un redemarrage.
    if state
        .db
        .execute(
            "INSERT INTO oauth_states (state, verifier, redirect_to, created_at) VALUES ($1, $2, $3, $4)",
            params!(
                etat.clone(),
                verifier,
                q.redirect.clone().unwrap_or_default(),
                chrono::Utc::now().to_rfc3339()
            ),
        )
        .await
        .is_err()
    {
        return erreur(StatusCode::INTERNAL_SERVER_ERROR, "db error");
    }

    let url = format!(
        "{}/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        cfg.base_url,
        encode(&cfg.client_id),
        encode(&cfg.redirect_uri),
        encode(&cfg.scope),
        encode(&etat),
        encode(&defi),
    );
    Redirect::temporary(&url).into_response()
}

/// Encodage minimal pour composant de requete. `urlencoding` n'est pas dans les
/// dependances et ces valeurs sont maitrisees (uuid, base64url, config) ; on
/// echappe malgre tout ce qui aurait un sens en URL.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

struct EtatEnAttente {
    verifier: String,
    redirect_to: String,
}

impl From<&mut hiqlite::Row<'_>> for EtatEnAttente {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            verifier: row.get("verifier"),
            redirect_to: row.get("redirect_to"),
        }
    }
}

struct JetonTrouve {
    id: i64,
}

impl From<&mut hiqlite::Row<'_>> for JetonTrouve {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id") }
    }
}

async fn callback(State(state): State<AppState>, Query(q): Query<CallbackQuery>) -> Response {
    let Some(cfg) = Config::from_env() else {
        return erreur(StatusCode::NOT_IMPLEMENTED, "SSO KonnectID non configure");
    };
    if let Some(e) = q.error {
        return erreur(StatusCode::UNAUTHORIZED, &format!("refus KonnectID: {e}"));
    }
    let (Some(code), Some(etat)) = (q.code, q.state) else {
        return erreur(StatusCode::BAD_REQUEST, "code ou state manquant");
    };

    // Le `state` est consomme : un code d'autorisation ne doit pas pouvoir etre
    // rejoue, et la ligne fait justement office de jeton a usage unique.
    let attente: Option<EtatEnAttente> = state
        .db
        .query_map_optional(
            "SELECT verifier, redirect_to FROM oauth_states WHERE state = $1 AND created_at > $2",
            params!(
                etat.clone(),
                (chrono::Utc::now() - chrono::Duration::minutes(STATE_MINUTES)).to_rfc3339()
            ),
        )
        .await
        .unwrap_or(None);
    let _ = state
        .db
        .execute("DELETE FROM oauth_states WHERE state = $1", params!(etat))
        .await;

    let Some(attente) = attente else {
        return erreur(StatusCode::BAD_REQUEST, "state inconnu ou expire");
    };

    // Echange du code. Corps PLAT, pas d'enveloppe tRPC a l'aller.
    let client = reqwest::Client::new();
    let rep = client
        .post(format!("{}/api/trpc/oauth2.token", cfg.base_url))
        .json(&serde_json::json!({
            "grantType": "authorization_code",
            "code": code,
            "clientId": cfg.client_id,
            "clientSecret": cfg.client_secret,
            "redirectUri": cfg.redirect_uri,
            "codeVerifier": attente.verifier,
        }))
        .send()
        .await;
    let Ok(rep) = rep else {
        return erreur(StatusCode::BAD_GATEWAY, "KonnectID injoignable");
    };
    let Ok(corps): Result<serde_json::Value, _> = rep.json().await else {
        return erreur(StatusCode::BAD_GATEWAY, "reponse KonnectID illisible");
    };
    let Some(acces) = deballe(&corps)
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return erreur(StatusCode::UNAUTHORIZED, "echange du code refuse");
    };

    // userInfo : requete tRPC, donc l'entree passe en parametre `input`.
    let rep = client
        .get(format!(
            "{}/api/trpc/oauth2.userInfo?input={}",
            cfg.base_url,
            encode("{}")
        ))
        .bearer_auth(&acces)
        .send()
        .await;
    let Ok(rep) = rep else {
        return erreur(StatusCode::BAD_GATEWAY, "KonnectID injoignable (userInfo)");
    };
    let Ok(corps): Result<serde_json::Value, _> = rep.json().await else {
        return erreur(StatusCode::BAD_GATEWAY, "userInfo illisible");
    };
    let Some(email) = deballe(&corps)
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
    else {
        return erreur(StatusCode::UNAUTHORIZED, "email absent de KonnectID");
    };

    // Rapprochement avec un jeton EXISTANT. On ne cree jamais de compte ici :
    // se connecter ne doit pas provisionner du stockage sans decision de
    // l'exploitant. Sans jeton, l'utilisateur doit activer le stockage depuis
    // OxaDash.
    let jeton: Option<JetonTrouve> = state
        .db
        .query_map_optional(
            "SELECT id FROM tokens WHERE lower(owner) = $1",
            params!(email.clone()),
        )
        .await
        .unwrap_or(None);
    let Some(jeton) = jeton else {
        return erreur(
            StatusCode::FORBIDDEN,
            "aucun stockage associe a ce compte : active-le depuis OxaDash",
        );
    };

    let sid = uuid::Uuid::new_v4().to_string();
    let expire = (chrono::Utc::now() + chrono::Duration::days(SESSION_DAYS)).to_rfc3339();
    if state
        .db
        .execute(
            "INSERT INTO sessions (id, token_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
            params!(
                sid.clone(),
                jeton.id,
                chrono::Utc::now().to_rfc3339(),
                expire.clone()
            ),
        )
        .await
        .is_err()
    {
        return erreur(StatusCode::INTERNAL_SERVER_ERROR, "db error");
    }

    crate::audit::log(&state.db, jeton.id, "session.login", Some("session"), None, None).await;

    // `Secure` et `SameSite=Lax` : le cookie ne doit pas partir en clair, et Lax
    // suffit puisque la redirection de retour est une navigation de premier
    // niveau. `HttpOnly` : aucun script n'a besoin de le lire.
    let cookie = format!(
        "{SESSION_COOKIE}={sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        SESSION_DAYS * 86400
    );

    if attente.redirect_to.is_empty() {
        // Client lourd : pas de navigateur ou renvoyer, on rend la session.
        (
            [(header::SET_COOKIE, cookie)],
            Json(serde_json::json!({ "session": sid, "expires_at": expire })),
        )
            .into_response()
    } else {
        (
            [(header::SET_COOKIE, cookie)],
            Redirect::temporary(&attente.redirect_to),
        )
            .into_response()
    }
}

/// KonnectID enveloppe ses reponses tRPC dans `result.data`, parfois
/// `result.data.json`. On deballe les deux, et on retombe sur la racine si la
/// forme change.
fn deballe(v: &serde_json::Value) -> &serde_json::Value {
    let d = v.get("result").and_then(|r| r.get("data")).unwrap_or(v);
    d.get("json").unwrap_or(d)
}

async fn logout(State(state): State<AppState>, ctx: crate::auth::TokenCtx) -> Response {
    // On ne supprime que les sessions, jamais le jeton : se deconnecter d'un
    // navigateur ne doit pas couper les clients de bureau du meme compte.
    let _ = state
        .db
        .execute("DELETE FROM sessions WHERE token_id = $1", params!(ctx.id))
        .await;
    let expire = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
    ([(header::SET_COOKIE, expire)], StatusCode::NO_CONTENT).into_response()
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/konnect/login", get(login))
        .route("/auth/konnect/callback", get(callback))
        .route("/auth/logout", get(logout))
}
