//! WebDAV **en lecture seule** sur l'arborescence d'un jeton.
//!
//! POURQUOI : Plaste n'exposait que son API REST, adressée par identifiant
//! numérique (`/files/{id}/download`). Or beaucoup de logiciels ne savent lire
//! qu'un système de fichiers monté — LumiR, par exemple, attend sa médiathèque
//! sur un chemin, pas derrière une API. WebDAV est le plus petit dénominateur
//! commun qui rende l'arborescence montable (davfs2, rclone, gestionnaires de
//! fichiers de bureau) sans rien changer au stockage.
//!
//! LECTURE SEULE, délibérément. Les verbes d'écriture (PUT, MKCOL, DELETE,
//! MOVE, COPY, LOCK) ne sont pas implémentés : l'écriture passe déjà par des
//! chemins qui gèrent le découpage en chunks, la déduplication, les versions et
//! les quotas (`chunk_upload`, `tus`). Un PUT WebDAV naïf court-circuiterait
//! tout ça. Ajouter l'écriture demande de réutiliser ces chemins, pas de
//! réécrire un second téléversement.
//!
//! ADRESSAGE : `/dav/<dossier>/<sous-dossier>/<fichier>`, résolu par NOM depuis
//! la racine du jeton appelant. Les identifiants numériques n'apparaissent
//! jamais — c'est justement ce qui permet à un client de monter l'arborescence.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use hiqlite::params;

use crate::{auth::TokenCtx, AppState};

struct Dossier {
    id: i64,
    name: String,
}

impl From<&mut hiqlite::Row<'_>> for Dossier {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id"), name: row.get("name") }
    }
}

struct Fichier {
    id: i64,
    name: String,
    taille: i64,
}

impl From<&mut hiqlite::Row<'_>> for Fichier {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            // COALESCE côté SQL : un fichier sans version courante existe (envoi
            // interrompu) et doit être listé a taille nulle plutot que de faire
            // echouer tout le PROPFIND du dossier.
            taille: row.get("taille"),
        }
    }
}

/// Découpe un chemin DAV en segments, en refusant tout ce qui pourrait sortir
/// de l'arborescence. `..` n'a aucun sens ici : la résolution se fait par nom
/// depuis la racine du jeton, jamais par concaténation de chemin système.
fn segments(chemin: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for brut in chemin.split('/') {
        let s = percent_decode(brut);
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." || s.contains('\0') {
            return None;
        }
        out.push(s);
    }
    Some(out)
}

fn percent_decode(s: &str) -> String {
    let o = s.as_bytes();
    let mut out = Vec::with_capacity(o.len());
    let mut i = 0;
    while i < o.len() {
        if o[i] == b'%' && i + 2 < o.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(o[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn xml_echappe(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Encode un segment pour un href XML. Sans ça, un fichier nommé `a b&c.mp4`
/// produirait un href invalide et le client sauterait l'entree.
fn href_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Descend l'arborescence par nom. Rend l'id du dossier atteint.
/// `None` = un segment n'existe pas.
async fn resoudre_dossier(
    state: &AppState,
    token_id: i64,
    chemin: &[String],
) -> Option<Option<i64>> {
    let mut courant: Option<i64> = None; // None = racine (parent_id IS NULL)
    for nom in chemin {
        let trouve: Option<Dossier> = match courant {
            None => state
                .db
                .query_map_optional(
                    "SELECT id, name FROM folders WHERE parent_id IS NULL AND name = $1 \
                     AND owner_token_id = $2 AND deleted_at IS NULL",
                    params!(nom.clone(), token_id),
                )
                .await
                .ok()?,
            Some(p) => state
                .db
                .query_map_optional(
                    "SELECT id, name FROM folders WHERE parent_id = $1 AND name = $2 \
                     AND owner_token_id = $3 AND deleted_at IS NULL",
                    params!(p, nom.clone(), token_id),
                )
                .await
                .ok()?,
        };
        courant = Some(trouve?.id);
    }
    Some(courant)
}

async fn enfants(
    state: &AppState,
    token_id: i64,
    parent: Option<i64>,
) -> (Vec<Dossier>, Vec<Fichier>) {
    let dossiers: Vec<Dossier> = match parent {
        None => state.db.query_map(
            "SELECT id, name FROM folders WHERE parent_id IS NULL AND owner_token_id = $1 \
             AND deleted_at IS NULL ORDER BY name",
            params!(token_id),
        ).await.unwrap_or_default(),
        Some(p) => state.db.query_map(
            "SELECT id, name FROM folders WHERE parent_id = $1 AND owner_token_id = $2 \
             AND deleted_at IS NULL ORDER BY name",
            params!(p, token_id),
        ).await.unwrap_or_default(),
    };
    let fichiers: Vec<Fichier> = match parent {
        None => state.db.query_map(
            "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS taille FROM files f \
             LEFT JOIN file_versions v ON v.id = f.current_version_id \
             WHERE f.folder_id IS NULL AND f.owner_token_id = $1 AND f.deleted_at IS NULL ORDER BY f.name",
            params!(token_id),
        ).await.unwrap_or_default(),
        Some(p) => state.db.query_map(
            "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS taille FROM files f \
             LEFT JOIN file_versions v ON v.id = f.current_version_id \
             WHERE f.folder_id = $1 AND f.owner_token_id = $2 AND f.deleted_at IS NULL ORDER BY f.name",
            params!(p, token_id),
        ).await.unwrap_or_default(),
    };
    (dossiers, fichiers)
}

async fn fichier_par_nom(
    state: &AppState,
    token_id: i64,
    parent: Option<i64>,
    nom: &str,
) -> Option<Fichier> {
    match parent {
        None => state.db.query_map_optional(
            "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS taille FROM files f \
             LEFT JOIN file_versions v ON v.id = f.current_version_id \
             WHERE f.folder_id IS NULL AND f.name = $1 AND f.owner_token_id = $2 AND f.deleted_at IS NULL",
            params!(nom.to_string(), token_id),
        ).await.ok()?,
        Some(p) => state.db.query_map_optional(
            "SELECT f.id AS id, f.name AS name, COALESCE(v.size, 0) AS taille FROM files f \
             LEFT JOIN file_versions v ON v.id = f.current_version_id \
             WHERE f.folder_id = $1 AND f.name = $2 AND f.owner_token_id = $3 AND f.deleted_at IS NULL",
            params!(p, nom.to_string(), token_id),
        ).await.ok()?,
    }
}

fn entree_xml(href: &str, nom: &str, collection: bool, taille: i64) -> String {
    let type_res = if collection {
        "<D:resourcetype><D:collection/></D:resourcetype>".to_string()
    } else {
        format!(
            "<D:resourcetype/><D:getcontentlength>{taille}</D:getcontentlength>\
             <D:getcontenttype>{}</D:getcontenttype>",
            xml_echappe(mime_guess::from_path(nom).first_or_octet_stream().as_ref())
        )
    };
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>\
         <D:displayname>{}</D:displayname>{}</D:prop>\
         <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_echappe(href),
        xml_echappe(nom),
        type_res
    )
}

fn multistatus(corps: String) -> Response {
    (
        StatusCode::MULTI_STATUS,
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::HeaderName::from_static("dav"), "1"),
        ],
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">{corps}</D:multistatus>"#
        ),
    )
        .into_response()
}

async fn dav(
    State(state): State<AppState>,
    ctx: TokenCtx,
    methode: axum::http::Method,
    Path(chemin): Path<String>,
    entetes: HeaderMap,
) -> Response {
    let Some(segs) = segments(&chemin) else {
        return (StatusCode::BAD_REQUEST, "chemin invalide").into_response();
    };

    match methode.as_str() {
        "OPTIONS" => (
            StatusCode::OK,
            [
                (header::HeaderName::from_static("dav"), "1"),
                (header::ALLOW, "OPTIONS, PROPFIND, HEAD, GET"),
            ],
        )
            .into_response(),

        "PROPFIND" => {
            // `Depth: 0` = la ressource seule, `1` = elle et ses enfants. On ne
            // gere pas `infinity` : une profondeur illimitee sur une grosse
            // arborescence est un deni de service offert au client.
            let profondeur = entetes
                .get("depth")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("1");
            if profondeur == "infinity" {
                return (StatusCode::FORBIDDEN, "Depth: infinity refuse").into_response();
            }

            // Le chemin designe-t-il un dossier ?
            if let Some(parent) = resoudre_dossier(&state, ctx.id, &segs).await {
                let base = format!(
                    "/dav/{}",
                    segs.iter().map(|s| href_encode(s)).collect::<Vec<_>>().join("/")
                );
                let base = base.trim_end_matches('/').to_string();
                let nom = segs.last().cloned().unwrap_or_else(|| "/".to_string());
                let mut corps = entree_xml(&format!("{base}/"), &nom, true, 0);
                if profondeur != "0" {
                    let (dossiers, fichiers) = enfants(&state, ctx.id, parent).await;
                    for d in dossiers {
                        corps.push_str(&entree_xml(
                            &format!("{base}/{}/", href_encode(&d.name)),
                            &d.name,
                            true,
                            0,
                        ));
                    }
                    for f in fichiers {
                        corps.push_str(&entree_xml(
                            &format!("{base}/{}", href_encode(&f.name)),
                            &f.name,
                            false,
                            f.taille,
                        ));
                    }
                }
                return multistatus(corps);
            }

            // Sinon, peut-etre un fichier : le dernier segment est son nom.
            let Some((nom, parents)) = segs.split_last() else {
                return (StatusCode::NOT_FOUND, "introuvable").into_response();
            };
            let Some(parent) = resoudre_dossier(&state, ctx.id, parents).await else {
                return (StatusCode::NOT_FOUND, "introuvable").into_response();
            };
            match fichier_par_nom(&state, ctx.id, parent, nom).await {
                Some(f) => multistatus(entree_xml(
                    &format!("/dav/{}", segs.iter().map(|s| href_encode(s)).collect::<Vec<_>>().join("/")),
                    &f.name,
                    false,
                    f.taille,
                )),
                None => (StatusCode::NOT_FOUND, "introuvable").into_response(),
            }
        }

        "GET" | "HEAD" => {
            let Some((nom, parents)) = segs.split_last() else {
                return (StatusCode::NOT_FOUND, "introuvable").into_response();
            };
            let Some(parent) = resoudre_dossier(&state, ctx.id, parents).await else {
                return (StatusCode::NOT_FOUND, "introuvable").into_response();
            };
            let Some(f) = fichier_par_nom(&state, ctx.id, parent, nom).await else {
                return (StatusCode::NOT_FOUND, "introuvable").into_response();
            };

            let mime = mime_guess::from_path(&f.name).first_or_octet_stream().to_string();
            if methode == axum::http::Method::HEAD {
                // Pas de corps : un client video fait souvent un HEAD avant de
                // demander des plages, il lui faut la taille et Accept-Ranges.
                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, mime),
                        (header::CONTENT_LENGTH, f.taille.to_string()),
                        (header::ACCEPT_RANGES, "bytes".to_string()),
                    ],
                )
                    .into_response();
            }

            crate::files::servir_contenu(&state, f.id, &f.name, &entetes).await
        }

        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "OPTIONS, PROPFIND, HEAD, GET")],
            "WebDAV en lecture seule",
        )
            .into_response(),
    }
}

/// Ajoute `WWW-Authenticate` a tout 401 du sous-arbre WebDAV.
///
/// Sans cet en-tete, un client fait sa premiere requete sans identifiants,
/// recoit un 401 nu, et ABANDONNE au lieu de reessayer en Basic — le montage
/// echoue alors sans raison visible. Les clients d'API, eux, envoient le jeton
/// d'emblee et ne dependent pas de ce defi ; c'est pourquoi il est pose ici et
/// non sur tout le service.
async fn defi_authentification(mut reponse: Response) -> Response {
    if reponse.status() == StatusCode::UNAUTHORIZED {
        reponse.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Basic realm=\"Plaste\""),
        );
    }
    reponse
}

pub fn router() -> Router<AppState> {
    // `any` : PROPFIND n'est pas une methode HTTP standard, axum n'a pas de
    // routeur dedie. On aiguille nous-memes sur la methode.
    Router::new()
        .route("/dav", any(dav_racine))
        .route("/dav/{*chemin}", any(dav))
        .layer(axum::middleware::map_response(defi_authentification))
}

/// `/dav` sans chemin = la racine du jeton.
async fn dav_racine(
    state: State<AppState>,
    ctx: TokenCtx,
    methode: axum::http::Method,
    entetes: HeaderMap,
) -> Response {
    dav(state, ctx, methode, Path(String::new()), entetes).await
}

/// Corps d'une reponse vide, pour satisfaire le typage la ou axum attend un Body.
#[allow(dead_code)]
fn vide() -> Body {
    Body::empty()
}

#[cfg(test)]
mod tests {
    use super::{href_encode, percent_decode, segments, xml_echappe};

    #[test]
    fn decoupe_et_ignore_les_segments_vides() {
        assert_eq!(segments("/Films/2026/").unwrap(), vec!["Films", "2026"]);
        assert_eq!(segments("").unwrap(), Vec::<String>::new());
    }

    /// La resolution se fait par NOM depuis la racine du jeton, donc `..` n'a
    /// aucun sens — mais le refuser explicitement evite qu'un futur appelant
    /// qui concatenerait un chemin systeme ne sorte de l'arborescence.
    #[test]
    fn refuse_la_remontee_et_le_zero() {
        assert!(segments("/Films/../../etc/passwd").is_none());
        assert!(segments("/Films/%2e%2e/secret").is_none());
        assert!(segments("/a\0b").is_none());
    }

    /// Un nom accentue ou espace doit survivre a l'aller-retour, sinon le
    /// fichier devient introuvable une fois monte.
    #[test]
    fn decode_puis_reencode_un_nom_reel() {
        let nom = "Mon Film (2026) — édition finale.mp4";
        assert_eq!(percent_decode(&href_encode(nom)), nom);
    }

    #[test]
    fn echappe_le_xml() {
        assert_eq!(xml_echappe("a&b<c>"), "a&amp;b&lt;c&gt;");
    }
}
