// Cible de fuzzing : nettoyage du nom de fichier avant interpolation dans
// l'en-tete `Content-Disposition`.
//
// POURQUOI CELLE-CI.
//
// Le nom vient du televersement, donc de l'utilisateur, et finit dans un
// en-tete HTTP entre guillemets. S'il en survit un CR, un LF, un guillemet ou
// une contre-oblique, on a une injection d'en-tete : l'attaquant ajoute ses
// propres en-tetes a une reponse servie a la victime.
//
// On ne cherche donc pas une panique (la fonction est un simple filtre) mais
// une EVASION : un caractere structurant qui traverse. Le fuzzer explore ici
// les encodages exotiques d'Unicode que les tests de proprietes ne tirent
// jamais — separateurs de ligne U+2028, controles C1, etc.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|donnees: &[u8]| {
    let Ok(brut) = std::str::from_utf8(donnees) else {
        return;
    };

    let propre = plaste::sharing::sanitize_filename(brut);

    // INVARIANT 1 : aucun caractere ne peut fermer la chaine entre guillemets
    // ni entamer un nouvel en-tete.
    for c in propre.chars() {
        assert!(
            !c.is_control() && c != '"' && c != '\\',
            "caractere structurant survivant : {:?} (entree {:?})",
            c,
            brut
        );
    }

    // INVARIANT 2 : le resultat n'est jamais vide. Un `filename=""` est un
    // en-tete invalide, que certains clients rejettent et d'autres
    // interpretent — les deux sont des defauts.
    assert!(
        !propre.trim().is_empty(),
        "nom vide produit depuis {brut:?}"
    );
});
