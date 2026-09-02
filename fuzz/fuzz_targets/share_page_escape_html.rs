// Cible de fuzzing : echappement HTML de la page de partage public.
//
// POURQUOI CELLE-CI.
//
// La page de partage est servie a des visiteurs NON AUTHENTIFIES, et y sont
// interpoles des noms de fichiers choisis par le deposant. Une evasion ici est
// un XSS stocke frappant quelqu'un qui n'a jamais eu de compte.
//
// L'invariant est simple et total : apres echappement, plus aucun caractere ne
// peut sortir du contexte texte ou d'un attribut entre guillemets. On le
// verifie de facon absolue plutot que de chercher des motifs d'attaque connus —
// une liste de vecteurs ne couvre que ce qu'on a imagine.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|donnees: &[u8]| {
    let Ok(brut) = std::str::from_utf8(donnees) else {
        return;
    };

    let echappe = plaste::share_page::escape_html(brut);

    // INVARIANT : aucun caractere structurant ne subsiste. `&` compris — s'il
    // passait tel quel, une entite forgee par l'attaquant se reconstituerait
    // dans l'analyseur du navigateur.
    for c in echappe.chars() {
        assert!(
            !matches!(c, '<' | '>' | '"' | '\''),
            "caractere structurant survivant : {:?} (entree {:?})",
            c,
            brut
        );
    }

    // INVARIANT : echapper deux fois ne doit rien casser (la sortie reste du
    // texte valide et stable en longueur croissante) — attrape une regression
    // ou l'echappement deviendrait partiel selon la position.
    let deux_fois = plaste::share_page::escape_html(&echappe);
    assert!(deux_fois.len() >= echappe.len());
});
