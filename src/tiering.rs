//! Automatic hot/cold chunk tiering ("Tiering hot/cold automatique").
//!
//! The actual tiering logic (tier-aware reads, sweep) lives on `ChunkStore`
//! (`storage.rs`) since that's the type every caller already holds — see
//! `ChunkStore::with_tiering`, `ChunkStore::run_tiering_sweep`. This module only
//! owns the tiering-specific schema, run separately from db.rs's shared SCHEMA
//! array (same pattern as tags.rs/comments.rs) to avoid touching code other
//! agents are editing.

/// Seuil d'inactivite avant demotion, en jours.
///
/// 2 par defaut. Avec les 30 jours codes en dur precedemment, un service actif
/// ne demouvait quasiment rien : mesure du 02/09/2026, 892 chunks chauds pour 1
/// seul froid, alors que le mecanisme fonctionnait. `last_accessed` etant
/// rafraichi a CHAQUE lecture, 30 jours signifie 30 jours sans le moindre acces.
pub const JOURS_DEFAUT: i64 = 2;

/// Plafond du palier chaud, en octets (50 Gio par defaut).
///
/// Une eviction par AGE seule ne borne pas la taille : une rafale d'envois sur
/// une seule journee reste sous le seuil de temps tout en remplissant le disque.
/// Or le palier chaud partage `sda` avec le reste du cluster, et c'est ce disque
/// qui est passe en DiskPressure le 02/09/2026 — le ramasse-miettes de kubelet a
/// alors elague des images encore en service. Le plafond en taille est donc une
/// protection, pas un reglage de confort.
pub const PLAFOND_CHAUD_DEFAUT: i64 = 50 * 1024 * 1024 * 1024;

/// Reglages du palier, surchargeables par l'environnement.
///
/// `PLASTE_TIER_COLD_AFTER_DAYS` : jours d'inactivite avant demotion.
/// `PLASTE_TIER_HOT_MAX_BYTES`   : plafond du palier chaud en octets ; `0`
///                                 desactive l'eviction par taille.
pub fn reglages() -> (i64, Option<i64>) {
    let jours = std::env::var("PLASTE_TIER_COLD_AFTER_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|j| *j >= 0)
        .unwrap_or(JOURS_DEFAUT);
    let plafond = std::env::var("PLASTE_TIER_HOT_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(PLAFOND_CHAUD_DEFAUT);
    (jours, if plafond > 0 { Some(plafond) } else { None })
}

/// Own schema for tiering, run separately from db.rs's SCHEMA array.
pub async fn init_schema(db: &hiqlite::Client) {
    const SCHEMA: &[&str] = &[r#"CREATE TABLE IF NOT EXISTS chunk_access (
        hash TEXT PRIMARY KEY,
        tier TEXT NOT NULL DEFAULT 'hot',
        last_accessed TEXT NOT NULL,
        bytes INTEGER NOT NULL DEFAULT 0
    )"#];
    for stmt in SCHEMA {
        db.execute(*stmt, hiqlite::params!()).await.expect("tiering schema migration");
    }

    // Taille REELLE du blob, indispensable a l'eviction par taille.
    //
    // On ne peut PAS se servir de `chunks.size` : `files::store_new_version`
    // appelle `bump_or_insert_chunk_refcount(state, hash, size)` pour chaque
    // entree du manifeste en passant la taille du FICHIER entier, pas celle du
    // chunk. En prod le 02/09/2026, 304 lignes de `chunks` totalisaient ainsi
    // 341 Go pour 1,1 Go reellement sur le disque — et 588 chunks chauds sur 892
    // n'y avaient aucune ligne du tout.
    //
    // Migration tolerante, comme ailleurs dans le projet : la colonne existe
    // deja sur toute base creee apres ce commit.
    if let Err(e) = db
        .execute("ALTER TABLE chunk_access ADD COLUMN bytes INTEGER NOT NULL DEFAULT 0", hiqlite::params!())
        .await
    {
        tracing::debug!("skipping chunk_access.bytes ALTER (likely already applied): {e}");
    }
}
