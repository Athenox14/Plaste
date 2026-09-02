// Cible de fuzzing : mise a longueur fixe de l'identifiant de clef.
//
// POURQUOI CELLE-CI.
//
// La fonction est minuscule, mais son resultat prefixe chaque objet chiffre :
// c'est lui qui dit avec QUELLE clef dechiffrer. Deux identifiants distincts
// qui se replieraient sur le meme remplissage rendraient le prefixe ambigu.
// Elle decoupe par ailleurs `as_bytes()` a un indice fixe, ce qui vaut d'etre
// mis a l'epreuve sur de l'UTF-8 multi-octets.
//
// Cible peu couteuse : elle ne trouvera sans doute rien, mais elle est dans la
// campagne pour quelques secondes par nuit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use plaste::crypto::{pad_id, KEY_ID_LEN};

fuzz_target!(|donnees: &[u8]| {
    let Ok(brut) = std::str::from_utf8(donnees) else {
        return;
    };

    let rempli = pad_id(brut);

    // INVARIANT : longueur constante, et le prefixe reproduit fidelement
    // l'entree. Sans ca, deux clefs differentes pourraient se confondre.
    assert_eq!(rempli.len(), KEY_ID_LEN);
    let n = brut.as_bytes().len().min(KEY_ID_LEN);
    assert_eq!(&rempli[..n], &brut.as_bytes()[..n]);
});
