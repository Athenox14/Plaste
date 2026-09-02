// Cible de fuzzing : extraction des mentions `@utilisateur` d'un commentaire.
//
// POURQUOI CELLE-CI.
//
// Le corps du commentaire est du texte libre, ecrit par un utilisateur, et ce
// que cette fonction en tire sert ENSUITE a resoudre des comptes et a envoyer
// des notifications. Une entree degeneree (des dizaines de milliers de `@`)
// est un vecteur d'amplification : un commentaire, une avalanche de
// notifications. On borne donc le nombre de mentions rendues.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|donnees: &[u8]| {
    let Ok(brut) = std::str::from_utf8(donnees) else {
        return;
    };

    let mentions = plaste::comments::extract_mentions(brut);

    // INVARIANT : on ne peut pas produire plus de mentions qu'il n'y a de `@`
    // dans le corps. Un depassement signalerait une amplification.
    let arobases = brut.chars().filter(|c| *c == '@').count();
    assert!(
        mentions.len() <= arobases,
        "{} mentions pour {} arobases",
        mentions.len(),
        arobases
    );
});
