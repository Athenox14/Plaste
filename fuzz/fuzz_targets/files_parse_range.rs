// Cible de fuzzing : analyse de l'en-tete HTTP `Range`.
//
// POURQUOI CELLE-CI.
//
// C'est la cible la plus dangereuse du lot. `parse_range` rend un couple
// (debut, fin) qui sert ENSUITE a decouper un tampon. Deux facons de se
// planter :
//   - une panique (indice hors bornes, soustraction qui deborde en debug),
//     donc un deni de service par un simple en-tete ;
//   - pire, un couple hors bornes rendu comme valide, donc une lecture au-dela
//     du fichier — divulgation de memoire.
//
// La deuxieme ne se voit pas avec une simple recherche de panique : on verifie
// donc explicitement l'invariant de bornes ci-dessous. C'est la difference
// entre fuzzer pour la robustesse et fuzzer pour la correction.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|donnees: &[u8]| {
    // Le fuzzer choisit AUSSI la taille totale : le comportement de la fonction
    // en depend entierement (suffixes, bornes ouvertes, fichier vide). La figer
    // laisserait la moitie des branches inatteignables.
    if donnees.len() < 8 {
        return;
    }
    let (entete_taille, reste) = donnees.split_at(8);
    let total: usize = u64::from_le_bytes(entete_taille.try_into().unwrap()) as usize;

    let Ok(brut) = std::str::from_utf8(reste) else {
        return;
    };

    if let Some((debut, fin)) = plaste::files::parse_range(brut, total) {
        // INVARIANT : tout couple rendu doit etre decoupable sans risque dans un
        // tampon de `total` octets. Un manquement ici est une divulgation de
        // memoire, pas un simple plantage.
        assert!(debut <= fin, "intervalle inverse : {debut}..{fin}");
        assert!(
            fin < total,
            "fin hors bornes : {fin} pour une taille de {total}"
        );
    }
});
