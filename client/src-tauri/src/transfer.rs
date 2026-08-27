//! Transferts en flux (téléversement / téléchargement) + diagnostic de connexion.
//!
//! POURQUOI un module à part de `api_client.rs` : les fonctions existantes là-bas prennent
//! et rendent des `Vec<u8>` — tout le fichier en mémoire. Plaste existe pour de GROS
//! fichiers ; charger 20 Gio en RAM (et les faire traverser le pont IPC de Tauri en JSON)
//! n'est pas une option. Ici, rien n'est jamais entièrement en mémoire : on lit le fichier
//! local par tranches et on parle le protocole tus 1.0 du serveur (`src/tus.rs`), qui est
//! justement conçu pour ça — et qui donne la reprise après coupure en prime.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Taille d'une tranche PATCH. 8 Mio : assez gros pour ne pas payer un aller-retour HTTP
/// tous les quatre octets, assez petit pour que l'annulation réagisse vite et que
/// l'empreinte mémoire reste constante quelle que soit la taille du fichier.
const CHUNK: usize = 8 * 1024 * 1024;

// ---------- annulation ----------

/// Drapeaux d'annulation, indexés par l'identifiant de transfert choisi par l'interface.
///
/// ponytail: une simple map globale sous mutex, pas de gestionnaire de tâches — un client
/// de bureau fait quelques transferts simultanés, pas dix mille.
fn cancels() -> &'static Mutex<HashMap<String, Arc<AtomicBool>>> {
    static C: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register(id: &str) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    cancels().lock().unwrap().insert(id.to_string(), flag.clone());
    flag
}

fn unregister(id: &str) {
    cancels().lock().unwrap().remove(id);
}

#[tauri::command]
pub fn transfer_cancel(transfer_id: String) {
    if let Some(flag) = cancels().lock().unwrap().get(&transfer_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

// ---------- progression ----------

#[derive(Clone, Serialize)]
struct Progress {
    transfer_id: String,
    transferred: u64,
    total: u64,
}

/// Émet un événement de progression. Volontairement limité : l'interface n'a pas besoin
/// d'un événement par tranche de 64 Kio, seulement de quoi bouger une barre.
fn emit(app: &AppHandle, transfer_id: &str, transferred: u64, total: u64) {
    let _ = app.emit(
        "transfer://progress",
        Progress { transfer_id: transfer_id.to_string(), transferred, total },
    );
}

// ---------- messages d'erreur réseau ----------

/// Traduit une erreur `reqwest` en phrase compréhensible.
///
/// POURQUOI : une trace brute (`error sending request for url ... Custom { kind: Other,
/// error: InvalidCertificate(UnknownIssuer) }`) ne dit rien à l'utilisateur. Les trois cas
/// qu'il doit pouvoir distinguer sont : je me suis trompé d'adresse, le certificat n'est
/// pas accepté, le serveur ne répond pas.
pub fn humanize(err: &reqwest::Error) -> String {
    // La cause utile est souvent enfouie dans la chaîne de sources ; on l'aplatit.
    let mut chain = err.to_string().to_lowercase();
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(e) = src {
        chain.push_str(&format!(" / {}", e).to_lowercase());
        src = e.source();
    }

    if chain.contains("certificat") || chain.contains("certificate") || chain.contains("tls")
        || chain.contains("unknownissuer") || chain.contains("self-signed")
    {
        return "Certificat TLS refusé : le serveur présente un certificat que ce système ne \
                reconnaît pas (auto-signé, expiré, ou nom d'hôte différent)."
            .into();
    }
    if err.is_timeout() {
        return "Délai dépassé : le serveur n'a pas répondu à temps.".into();
    }
    if err.is_connect() {
        return "Hôte injoignable : vérifiez l'adresse, le port, et que le serveur est démarré."
            .into();
    }
    if chain.contains("dns") || chain.contains("resolve") || chain.contains("nodename") {
        return "Nom d'hôte introuvable : la résolution DNS de cette adresse a échoué.".into();
    }
    format!("Erreur réseau : {}", err)
}

fn http() -> reqwest::Client {
    // ponytail: un client neuf par commande. Tauri sérialise chaque appel séparément, et le
    // coût d'un pool TCP tout neuf est négligeable devant un transfert de plusieurs Gio.
    reqwest::Client::new()
}

// ---------- diagnostic de connexion ----------

#[derive(Serialize)]
pub struct ProbeResult {
    /// Vrai si le serveur répond comme un serveur Plaste (401 sans jeton, ou 200 avec).
    pub is_plaste: bool,
    /// Vrai si le jeton fourni est accepté.
    pub authenticated: bool,
    pub message: String,
}

/// Teste une URL (et éventuellement un jeton) sans rien écrire.
///
/// POURQUOI `GET /folders` comme sonde : c'est la route de listage racine, elle existe
/// forcément sur un serveur Plaste (`src/folders.rs`) et elle exige l'authentification.
/// Sans jeton elle répond donc 401 — une empreinte fiable. Un 404 signifie qu'on parle à
/// un serveur web quelconque, pas à Plaste. (Il n'y a PAS de route `/whoami` en
/// production : elle n'existe que dans le routeur de test de `src/auth.rs`.)
#[tauri::command]
pub async fn server_probe(base_url: String, token: Option<String>) -> Result<ProbeResult, String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    let mut req = http()
        .get(format!("{base_url}/folders"))
        .timeout(std::time::Duration::from_secs(15));
    if let Some(t) = token.as_deref().filter(|t| !t.trim().is_empty()) {
        req = req.bearer_auth(t.trim());
    }

    let resp = req.send().await.map_err(|e| humanize(&e))?;
    let status = resp.status();
    Ok(match status.as_u16() {
        200 => ProbeResult {
            is_plaste: true,
            authenticated: true,
            message: "Connecté : serveur Plaste et jeton valides.".into(),
        },
        401 => ProbeResult {
            is_plaste: true,
            authenticated: false,
            message: if token.is_some() {
                "Serveur Plaste joignable, mais le jeton est refusé (invalide ou expiré).".into()
            } else {
                "Serveur Plaste joignable. Saisissez maintenant votre jeton d'accès.".into()
            },
        },
        403 => ProbeResult {
            is_plaste: true,
            authenticated: false,
            message: "Serveur Plaste joignable, mais ce jeton n'a pas les droits nécessaires."
                .into(),
        },
        404 => ProbeResult {
            is_plaste: false,
            authenticated: false,
            message: "Ce n'est pas un serveur Plaste : l'adresse répond, mais la route /folders \
                      est inconnue. Vérifiez l'URL (préfixe de chemin oublié ?)."
                .into(),
        },
        429 => ProbeResult {
            is_plaste: true,
            authenticated: false,
            message: "Trop de requêtes : le serveur applique une limite de débit. Réessayez \
                      dans une minute."
                .into(),
        },
        s if s >= 500 => ProbeResult {
            is_plaste: false,
            authenticated: false,
            message: format!("Le serveur a répondu {s} : panne côté serveur, ou un proxy qui \
                              n'atteint pas Plaste."),
        },
        s => ProbeResult {
            is_plaste: false,
            authenticated: false,
            message: format!("Réponse inattendue ({s}) : cette adresse ne se comporte pas comme \
                              un serveur Plaste."),
        },
    })
}

// ---------- téléversement en flux (tus) ----------

/// Encode les métadonnées tus : paires `clé base64(valeur)` séparées par des virgules
/// (voir `parse_metadata` dans `src/tus.rs`, qui attend du base64 standard).
fn tus_metadata(name: &str, folder_id: Option<i64>) -> String {
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    let mut parts = vec![format!("filename {}", b64(name))];
    if let Some(id) = folder_id {
        parts.push(format!("folder_id {}", b64(&id.to_string())));
    }
    parts.join(",")
}

#[derive(Serialize)]
pub struct UploadOutcome {
    pub name: String,
    pub size: u64,
    /// Rempli si le serveur a signalé un conflit (en-têtes `x-conflict*` du PATCH final).
    pub conflicted_copy_name: Option<String>,
}

#[tauri::command]
pub async fn upload_stream(
    app: AppHandle,
    base_url: String,
    token: String,
    path: String,
    folder_id: Option<i64>,
    transfer_id: String,
) -> Result<UploadOutcome, String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    let file_path = std::path::PathBuf::from(&path);
    let name = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Nom de fichier illisible.")?
        .to_string();

    let mut file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|e| format!("Impossible d'ouvrir « {name} » : {e}"))?;
    let total = file
        .metadata()
        .await
        .map_err(|e| format!("Impossible de lire la taille de « {name} » : {e}"))?
        .len();

    let client = http();

    // 1. Création : on annonce la taille totale, le serveur vérifie le quota tout de suite.
    let created = client
        .post(format!("{base_url}/tus/uploads"))
        .bearer_auth(&token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Length", total.to_string())
        .header("Upload-Metadata", tus_metadata(&name, folder_id))
        .send()
        .await
        .map_err(|e| humanize(&e))?;

    if created.status() == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
        return Err(format!(
            "Quota dépassé : « {name} » ({}) ne tient pas dans l'espace restant sur le serveur.",
            human_size(total)
        ));
    }
    if !created.status().is_success() {
        return Err(status_message(created.status(), "création du téléversement"));
    }
    let location = created
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or("Le serveur n'a pas renvoyé d'en-tête Location pour ce téléversement.")?
        .to_string();
    // `Location` est relatif (`/tus/uploads/<id>`) dans src/tus.rs — on le préfixe.
    let upload_url = if location.starts_with("http") {
        location
    } else {
        format!("{base_url}{location}")
    };

    let cancel = register(&transfer_id);
    let result = patch_loop(
        &app, &client, &upload_url, &token, &mut file, total, &transfer_id, &cancel, &name,
    )
    .await;
    unregister(&transfer_id);

    match result {
        Ok(conflicted_copy_name) => Ok(UploadOutcome { name, size: total, conflicted_copy_name }),
        Err(e) => {
            // Annulation ou échec : on demande au serveur d'oublier le partiel (extension
            // tus « termination »), sinon les octets déjà envoyés restent sur son disque.
            let _ = client.delete(&upload_url).bearer_auth(&token)
                .header("Tus-Resumable", "1.0.0").send().await;
            Err(e)
        }
    }
}

/// Boucle d'envoi. Ne garde en mémoire qu'un tampon de `CHUNK` octets, réutilisé.
#[allow(clippy::too_many_arguments)]
async fn patch_loop(
    app: &AppHandle,
    client: &reqwest::Client,
    upload_url: &str,
    token: &str,
    file: &mut tokio::fs::File,
    total: u64,
    transfer_id: &str,
    cancel: &AtomicBool,
    name: &str,
) -> Result<Option<String>, String> {
    let mut offset: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    let mut conflicted_copy_name = None;

    emit(app, transfer_id, 0, total);

    while offset < total {
        if cancel.load(Ordering::Relaxed) {
            return Err(format!("Téléversement de « {name} » annulé."));
        }

        // Lecture depuis l'offset courant. On repositionne explicitement : si un PATCH a
        // échoué et qu'on reprend, le curseur du fichier ne correspond plus à l'offset que
        // le serveur a réellement accepté.
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| format!("Lecture de « {name} » impossible : {e}"))?;
        let want = std::cmp::min(CHUNK as u64, total - offset) as usize;
        let mut filled = 0;
        while filled < want {
            let n = file
                .read(&mut buf[filled..want])
                .await
                .map_err(|e| format!("Lecture de « {name} » impossible : {e}"))?;
            if n == 0 {
                return Err(format!(
                    "« {name} » a été tronqué pendant l'envoi (attendu {total} octets)."
                ));
            }
            filled += n;
        }

        let resp = client
            .patch(upload_url)
            .bearer_auth(token)
            .header("Tus-Resumable", "1.0.0")
            .header("Content-Type", "application/offset+octet-stream")
            .header("Upload-Offset", offset.to_string())
            .body(buf[..filled].to_vec())
            .send()
            .await
            .map_err(|e| humanize(&e))?;

        if resp.status() == reqwest::StatusCode::CONFLICT {
            // Désynchronisation d'offset : on redemande au serveur où il en est et on reprend
            // de là. C'est exactement le mécanisme de reprise de tus.
            offset = head_offset(client, upload_url, token).await?;
            continue;
        }
        if !resp.status().is_success() {
            return Err(status_message(resp.status(), "envoi d'une tranche"));
        }

        if let Some(v) = resp.headers().get("x-conflicted-copy-name").and_then(|v| v.to_str().ok()) {
            conflicted_copy_name = Some(v.to_string());
        }

        offset = resp
            .headers()
            .get("upload-offset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(offset + filled as u64);
        emit(app, transfer_id, offset, total);
    }

    Ok(conflicted_copy_name)
}

async fn head_offset(
    client: &reqwest::Client,
    upload_url: &str,
    token: &str,
) -> Result<u64, String> {
    let resp = client
        .head(upload_url)
        .bearer_auth(token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .await
        .map_err(|e| humanize(&e))?;
    resp.headers()
        .get("upload-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "Le serveur n'a pas indiqué où reprendre le téléversement.".to_string())
}

// ---------- téléchargement en flux ----------

#[tauri::command]
pub async fn download_stream(
    app: AppHandle,
    base_url: String,
    token: String,
    file_id: i64,
    dest_path: String,
    transfer_id: String,
) -> Result<String, String> {
    let base_url = crate::account::normalize_base_url(&base_url)?;
    let resp = http()
        .get(format!("{base_url}/files/{file_id}/download"))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| humanize(&e))?;
    if !resp.status().is_success() {
        return Err(status_message(resp.status(), "téléchargement"));
    }
    let total = resp.content_length().unwrap_or(0);

    // On écrit dans un fichier `.part` : un téléchargement interrompu ne doit pas laisser un
    // fichier d'apparence complète à l'emplacement final.
    let final_path = std::path::PathBuf::from(&dest_path);
    let part_path = final_path.with_extension(format!(
        "{}part",
        final_path.extension().map(|e| format!("{}.", e.to_string_lossy())).unwrap_or_default()
    ));
    let mut out = tokio::fs::File::create(&part_path)
        .await
        .map_err(|e| format!("Impossible d'écrire dans {} : {e}", part_path.display()))?;

    let cancel = register(&transfer_id);
    let mut written: u64 = 0;
    let mut resp = resp;
    emit(&app, &transfer_id, 0, total);

    // `reqwest` rend des tranches de quelques dizaines de Kio : émettre un événement à
    // chaque fois inonderait le pont IPC (des milliers par seconde sur un lien rapide).
    // On ne signale donc la progression qu'à chaque mébioctet franchi.
    const EMIT_EVERY: u64 = 1024 * 1024;
    let mut last_emit: u64 = 0;

    let outcome: Result<(), String> = loop {
        if cancel.load(Ordering::Relaxed) {
            break Err("Téléchargement annulé.".to_string());
        }
        match resp.chunk().await {
            Ok(Some(bytes)) => {
                if let Err(e) = out.write_all(&bytes).await {
                    break Err(format!("Écriture sur le disque impossible : {e}"));
                }
                written += bytes.len() as u64;
                if written - last_emit >= EMIT_EVERY {
                    last_emit = written;
                    emit(&app, &transfer_id, written, total);
                }
            }
            Ok(None) => {
                emit(&app, &transfer_id, written, total);
                break Ok(());
            }
            Err(e) => break Err(humanize(&e)),
        }
    };
    unregister(&transfer_id);
    let _ = out.flush().await;
    drop(out);

    match outcome {
        Ok(()) => {
            tokio::fs::rename(&part_path, &final_path)
                .await
                .map_err(|e| format!("Impossible de finaliser {} : {e}", final_path.display()))?;
            Ok(final_path.display().to_string())
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&part_path).await;
            Err(e)
        }
    }
}

// ---------- utilitaires ----------

/// Traduit un code HTTP inattendu en phrase utilisable, en nommant l'étape en cours.
pub(crate) fn status_message(status: reqwest::StatusCode, step: &str) -> String {
    match status.as_u16() {
        401 => format!("Jeton refusé pendant le {step} : reconnectez-vous."),
        403 => format!("Droits insuffisants pour le {step}."),
        404 => format!("Introuvable côté serveur pendant le {step}."),
        413 => format!("Quota dépassé pendant le {step}."),
        429 => format!("Limite de débit du serveur atteinte pendant le {step} ; réessayez."),
        s if s >= 500 => format!("Erreur serveur ({s}) pendant le {step}."),
        s => format!("Réponse inattendue ({s}) pendant le {step}."),
    }
}

/// Formate une taille en octets. Base 1024, une décimale au-delà du kibioctet.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["o", "Kio", "Mio", "Gio", "Tio"];
    if bytes < 1024 {
        return format!("{bytes} o");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taille_lisible() {
        assert_eq!(human_size(0), "0 o");
        assert_eq!(human_size(1023), "1023 o");
        assert_eq!(human_size(1024), "1.0 Kio");
        assert_eq!(human_size(1536), "1.5 Kio");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5.0 Gio");
        // Ne doit pas déborder au-delà de la dernière unité connue.
        assert!(human_size(u64::MAX).ends_with("Tio"));
    }

    #[test]
    fn metadonnees_tus_sont_du_base64() {
        // « essai.bin » -> ZXNzYWkuYmlu, 42 -> NDI (base64 standard, comme src/tus.rs l'attend)
        assert_eq!(tus_metadata("essai.bin", None), "filename ZXNzYWkuYmlu");
        assert_eq!(tus_metadata("essai.bin", Some(42)), "filename ZXNzYWkuYmlu,folder_id NDI=");
    }
}
