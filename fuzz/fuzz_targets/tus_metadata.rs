// Cible de fuzzing : decodage de l'en-tete tus `Upload-Metadata`.
//
// POURQUOI CELLE-CI EN PREMIER.
//
// C'est la surface la plus exposee du service : une chaine arbitraire, envoyee
// dans un en-tete HTTP par n'importe qui, decodee AVANT toute verification
// metier. La fonction est pure — pas de base, pas de reseau, pas de disque —
// donc le fuzzer atteint des centaines de milliers d'executions par seconde.
// A l'inverse, les chemins qui passent par Argon2id ou hiqlite sont lents par
// construction et feraient de mauvaises cibles.
//
// Ce qu'on cherche : une panique. En Rust, une panique dans un gestionnaire de
// requete est un deni de service — un seul en-tete suffirait. Les proprietes
// dans `src/tus.rs` couvrent deja les invariants sur des entrees aleatoires ;
// le fuzzing guide par couverture va chercher les cas que le hasard ne tire
// jamais (frontieres de base64, UTF-8 tronque, sequences degenerees).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|donnees: &[u8]| {
    // L'en-tete arrive comme du texte : on ne fuzze donc que des entrees
    // decodables en UTF-8, sinon la couche HTTP les aurait deja rejetees et on
    // depenserait le budget dans un cas impossible.
    if let Ok(brut) = std::str::from_utf8(donnees) {
        let _ = plaste::tus::parse_metadata(brut);
    }
});
