//! Compte : URL du serveur Plaste + jeton d'accès.
//!
//! POURQUOI ce module : le client ne doit être lié à AUCUN hébergeur. Comme le client
//! Nextcloud, l'utilisateur saisit l'URL de SON serveur au premier lancement. Il n'y a
//! donc aucune URL en dur ici, ni ailleurs dans le client.
//!
//! Séparation volontaire des deux secrets :
//!   - l'URL n'est pas un secret → simple fichier JSON dans le dossier de config de l'app ;
//!   - le jeton EST un secret → trousseau du système d'exploitation via le crate `keyring`
//!     (Credential Manager sous Windows, Keychain sous macOS, Secret Service sous Linux).
//!     Jamais en clair sur le disque. Voir `token_get`/`token_set`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

/// Service sous lequel le jeton est rangé dans le trousseau. Le "compte" est l'URL du
/// serveur : ça permet à un même utilisateur d'avoir un jeton par serveur Plaste.
const KEYRING_SERVICE: &str = "dev.plaste.client";

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ServerConfig {
    /// URL de base normalisée (sans slash final), p. ex. `https://plaste.exemple.org`.
    pub base_url: String,
}

fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("server.json"))
}

/// Normalise ce que l'utilisateur a tapé en URL de base utilisable.
///
/// POURQUOI : les gens tapent `plaste.exemple.org`, `https://plaste.exemple.org/`, ou même
/// avec des espaces collés par un copier-coller. Construire les URL de routes par simple
/// concaténation (`{base}/folders`) n'est correct que si la base est déjà propre — donc on
/// nettoie une fois, ici, plutôt qu'à chaque appel.
///
/// Le schéma par défaut est `https` : un client de stockage ne doit pas silencieusement
/// dégrader vers du HTTP en clair parce que l'utilisateur a omis le schéma.
pub fn normalize_base_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Indiquez l'adresse de votre serveur Plaste.".into());
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    if !with_scheme.starts_with("http://") && !with_scheme.starts_with("https://") {
        return Err("Seules les adresses http:// et https:// sont acceptées.".into());
    }
    // On enlève les slashs finaux ET un éventuel fragment/query collé par le navigateur.
    let cleaned = with_scheme
        .split(['#', '?'])
        .next()
        .unwrap_or(&with_scheme)
        .trim_end_matches('/')
        .to_string();
    // Après nettoyage il doit rester un hôte, pas juste `https://`.
    let host = cleaned.split("://").nth(1).unwrap_or("");
    if host.is_empty() {
        return Err("Adresse incomplète : il manque le nom d'hôte.".into());
    }
    Ok(cleaned)
}

#[tauri::command]
pub fn server_get(app: AppHandle) -> Result<Option<ServerConfig>, String> {
    let path = config_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    // Un fichier corrompu ne doit pas bloquer le démarrage : on repart sur l'écran de config.
    Ok(serde_json::from_str(&raw).ok())
}

#[tauri::command]
pub fn server_set(app: AppHandle, base_url: String) -> Result<ServerConfig, String> {
    let cfg = ServerConfig { base_url: normalize_base_url(&base_url)? };
    let path = config_path(&app)?;
    std::fs::write(&path, serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(cfg)
}

// ---------- jeton : trousseau système ----------

fn entry(base_url: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, base_url)
        .map_err(|e| format!("Trousseau système inaccessible : {e}"))
}

#[tauri::command]
pub fn token_set(base_url: String, token: String) -> Result<(), String> {
    let base_url = normalize_base_url(&base_url)?;
    if token.trim().is_empty() {
        return Err("Le jeton est vide.".into());
    }
    entry(&base_url)?
        .set_password(token.trim())
        .map_err(|e| format!("Impossible d'enregistrer le jeton dans le trousseau : {e}"))
}

/// Renvoie `None` si aucun jeton n'est enregistré pour ce serveur — cas normal au premier
/// lancement, donc pas une erreur.
#[tauri::command]
pub fn token_get(base_url: String) -> Result<Option<String>, String> {
    let base_url = normalize_base_url(&base_url)?;
    match entry(&base_url)?.get_password() {
        Ok(t) => Ok(Some(t)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Lecture du trousseau impossible : {e}")),
    }
}

#[tauri::command]
pub fn token_clear(base_url: String) -> Result<(), String> {
    let base_url = normalize_base_url(&base_url)?;
    match entry(&base_url)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Suppression du jeton impossible : {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_base_url;

    #[test]
    fn normalise_les_saisies_courantes() {
        assert_eq!(normalize_base_url("plaste.exemple.org").unwrap(), "https://plaste.exemple.org");
        assert_eq!(normalize_base_url("  https://p.org/  ").unwrap(), "https://p.org");
        assert_eq!(normalize_base_url("http://localhost:8080").unwrap(), "http://localhost:8080");
        assert_eq!(normalize_base_url("https://p.org/?x=1").unwrap(), "https://p.org");
        assert_eq!(normalize_base_url("https://p.org/sous/chemin").unwrap(), "https://p.org/sous/chemin");
    }

    #[test]
    fn refuse_les_saisies_inutilisables() {
        assert!(normalize_base_url("").is_err());
        assert!(normalize_base_url("   ").is_err());
        assert!(normalize_base_url("ftp://p.org").is_err());
        assert!(normalize_base_url("https://").is_err());
    }
}
