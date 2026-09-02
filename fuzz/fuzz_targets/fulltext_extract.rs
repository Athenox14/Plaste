// Cible de fuzzing : extraction du texte indexable d'un fichier televerse.
//
// POURQUOI CELLE-CI.
//
// C'est la seule fonction du service qui digere le CONTENU BRUT d'un fichier
// arbitraire. Tout le reste ne voit que des en-tetes ou des identifiants ; ici
// on passe des octets entierement choisis par l'utilisateur a un decodeur, puis
// on tronque le resultat. Deux pieges classiques :
//   - troncature a une frontiere de caractere multi-octets, qui panique si elle
//     est faite sur des indices d'octets d'une `String` ;
//   - explosion memoire ou temps quadratique sur une entree degeneree.
//
// Le nom est fuzze en meme temps que le contenu : c'est lui qui choisit la
// branche de decodage, le figer laisserait la plupart des types inatteignables.
#![no_main]

use libfuzzer_sys::fuzz_target;
use plaste::fulltext::FullTextIndex;

fuzz_target!(|donnees: &[u8]| {
    // Premier octet nul = separateur entre le nom et le contenu. Simple, et
    // suffisant pour que le fuzzer apprenne a faire varier les deux.
    let (nom, contenu) = match donnees.iter().position(|o| *o == 0) {
        Some(i) => (&donnees[..i], &donnees[i + 1..]),
        None => (&b"fichier.txt"[..], donnees),
    };
    let Ok(nom) = std::str::from_utf8(nom) else {
        return;
    };

    if let Some(texte) = FullTextIndex::extractable_content(nom, contenu) {
        // INVARIANT : la sortie est de l'UTF-8 valide et bornee. Le simple fait
        // de la parcourir attrape une troncature faite a la mauvaise frontiere.
        let _ = texte.chars().count();
    }
});
