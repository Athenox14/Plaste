//! Opérations distantes « courtes » (rien à mettre en flux) : parcours de l'arborescence,
//! renommage/déplacement/suppression, et création d'un lien de partage public.
//!
//! POURQUOI ici et pas dans `api_client.rs` : celui-ci existe pour le moteur de sync et
//! porte un cache mémoire des octets téléchargés, inutile (et nuisible) pour l'interface.
//! Ici on veut au contraire des messages d'erreur destinés à l'utilisateur — d'où la
//! réutilisation de `transfer::humanize` / `status_message`.

use serde::{Deserialize, Serialize};

use crate::transfer::humanize;

#[derive(Serialize, Deserialize, Clone)]
pub struct SubFolder {
    pub id: i64,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub id: i64,
    pub name: String,
    pub size: i64,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FolderContents {
    pub folders: Vec<SubFolder>,
    pub files: Vec<FileEntry>,
}

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

/// Vérifie le code de statut et rend une phrase lisible, sinon désérialise le corps.
async fn json_or_message<T: for<'de> Deserialize<'de>>(
    resp: reqwest::Response,
    step: &str,
) -> Result<T, String> {
    if !resp.status().is_success() {
        return Err(crate::transfer::status_message(resp.status(), step));
    }
    resp.json::<T>()
        .await
        .map_err(|_| format!("Réponse illisible du serveur pendant {step}."))
}

/// Liste la racine (`folder_id == None`) ou un dossier.
#[tauri::command]
pub async fn remote_list(
    base_url: String,
    token: String,
    folder_id: Option<i64>,
) -> Result<FolderContents, String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    let url = match folder_id {
        Some(id) => format!("{base_url}/folders/{id}"),
        None => format!("{base_url}/folders"),
    };
    let resp = http()
        .get(url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| humanize(&e))?;
    json_or_message(resp, "le listage du dossier").await
}

#[tauri::command]
pub async fn remote_create_folder(
    base_url: String,
    token: String,
    name: String,
    parent_id: Option<i64>,
) -> Result<serde_json::Value, String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Donnez un nom au dossier.".into());
    }
    let resp = http()
        .post(format!("{base_url}/folders"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": name, "parent_id": parent_id }))
        .send()
        .await
        .map_err(|e| humanize(&e))?;
    json_or_message(resp, "la création du dossier").await
}

/// Renomme et/ou déplace un fichier (PATCH `/files/{id}`).
///
/// Note sur `folder_id` : le serveur distingue « champ absent » (ne pas toucher) de
/// « champ à null » (remonter à la racine). On n'envoie donc la clé que si demandé.
#[tauri::command]
pub async fn remote_update_file(
    base_url: String,
    token: String,
    file_id: i64,
    name: Option<String>,
    move_to_folder: bool,
    folder_id: Option<i64>,
) -> Result<serde_json::Value, String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    let mut body = serde_json::Map::new();
    if let Some(n) = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()) {
        body.insert("name".into(), serde_json::Value::String(n));
    }
    if move_to_folder {
        body.insert(
            "folder_id".into(),
            folder_id.map(|i| serde_json::json!(i)).unwrap_or(serde_json::Value::Null),
        );
    }
    if body.is_empty() {
        return Err("Rien à modifier.".into());
    }
    let resp = http()
        .patch(format!("{base_url}/files/{file_id}"))
        .bearer_auth(&token)
        .json(&serde_json::Value::Object(body))
        .send()
        .await
        .map_err(|e| humanize(&e))?;
    json_or_message(resp, "la modification du fichier").await
}

/// Supprime un fichier (corbeille côté serveur, cf. `src/trash.rs`).
#[tauri::command]
pub async fn remote_delete_file(
    base_url: String,
    token: String,
    file_id: i64,
) -> Result<(), String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    let resp = http()
        .delete(format!("{base_url}/files/{file_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| humanize(&e))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(crate::transfer::status_message(resp.status(), "la suppression"))
    }
}

// ---------- partage public ----------

#[derive(Serialize)]
pub struct ShareCreated {
    pub id: i64,
    pub share_token: String,
    /// URL complète à donner au destinataire — c'est ce que l'utilisateur veut copier.
    pub url: String,
    pub password_protected: bool,
}

#[derive(Deserialize)]
struct CreateShareResp {
    id: i64,
    share_token: String,
}

/// Crée un lien public vers un fichier ou un dossier.
///
/// `expires_at` doit être du RFC 3339 ou le serveur répond 400 (cf. DOC.md) ; on préfère
/// le refuser ici avec un message clair plutôt que de laisser passer un 400 nu.
#[tauri::command]
pub async fn share_create(
    base_url: String,
    token: String,
    resource_type: String,
    resource_id: i64,
    password: Option<String>,
    expires_at: Option<String>,
) -> Result<ShareCreated, String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    if resource_type != "file" && resource_type != "folder" {
        return Err("Type de ressource inattendu (attendu « file » ou « folder »).".into());
    }
    let password = password.filter(|p| !p.is_empty());
    let expires_at = expires_at.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if let Some(ref e) = expires_at {
        if chrono_like_rfc3339(e).is_err() {
            return Err("La date d'expiration doit être au format RFC 3339 \
                        (ex. 2026-12-31T23:59:59Z)."
                .into());
        }
    }

    let has_password = password.is_some();
    let resp = http()
        .post(format!("{base_url}/shares"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "resource_type": resource_type,
            "resource_id": resource_id,
            // Le serveur exige `permission` ; « read » est le seul sens pour un lien de
            // téléchargement public envoyé depuis un client de bureau.
            "permission": "read",
            "password": password,
            "expires_at": expires_at,
        }))
        .send()
        .await
        .map_err(|e| humanize(&e))?;

    let created: CreateShareResp = json_or_message(resp, "la création du lien de partage").await?;
    Ok(ShareCreated {
        id: created.id,
        url: format!("{base_url}/public/shares/{}", created.share_token),
        share_token: created.share_token,
        password_protected: has_password,
    })
}

/// Validation minimale du RFC 3339 sans ajouter `chrono` au client juste pour ça :
/// on exige la forme `AAAA-MM-JJThh:mm:ss` suivie d'un fuseau (`Z` ou `±hh:mm`).
///
/// ponytail: contrôle de forme, pas de calendrier — le serveur reste l'autorité et
/// renverra 400 sur un 31 février.
fn chrono_like_rfc3339(s: &str) -> Result<(), ()> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return Err(());
    }
    let digits_at = |idx: &[usize]| idx.iter().all(|&i| b[i].is_ascii_digit());
    if !digits_at(&[0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]) {
        return Err(());
    }
    if b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') || b[13] != b':' || b[16] != b':' {
        return Err(());
    }
    let tail = &s[19..];
    let tail = tail.strip_prefix('.').map_or(tail, |frac| {
        // Fraction de seconde optionnelle : on saute les chiffres.
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        &frac[n..]
    });
    if tail == "Z" || tail == "z" {
        return Ok(());
    }
    let signed = tail.strip_prefix('+').or_else(|| tail.strip_prefix('-')).ok_or(())?;
    let sb = signed.as_bytes();
    if sb.len() == 5 && sb[2] == b':' && sb[0].is_ascii_digit() && sb[1].is_ascii_digit()
        && sb[3].is_ascii_digit() && sb[4].is_ascii_digit()
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::chrono_like_rfc3339 as ok3339;

    #[test]
    fn accepte_du_rfc3339() {
        assert!(ok3339("2026-12-31T23:59:59Z").is_ok());
        assert!(ok3339("2026-12-31T23:59:59.123Z").is_ok());
        assert!(ok3339("2026-12-31T23:59:59+02:00").is_ok());
        assert!(ok3339("2026-12-31t23:59:59-05:00").is_ok());
    }

    #[test]
    fn refuse_le_reste() {
        assert!(ok3339("").is_err());
        assert!(ok3339("31/12/2026").is_err());
        assert!(ok3339("2026-12-31 23:59:59").is_err()); // espace au lieu de T
        assert!(ok3339("2026-12-31T23:59:59").is_err()); // fuseau manquant
        assert!(ok3339("2026-12-31T23:59:59+0200").is_err()); // deux-points manquant
    }
}
