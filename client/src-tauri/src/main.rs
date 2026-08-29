// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // Fenêtre entièrement blanche sous Linux (AppImage) alors que la même
    // version fonctionne sous Windows : WebKitGTK ne peint rien quand son rendu
    // DMA-BUF échoue, ce qui arrive sur beaucoup de configurations (pilotes
    // Nvidia, machines virtuelles, Wayland via XWayland). Le symptôme est un
    // blanc TOTAL, sans même le « Démarrage… » que l'interface rend pourtant de
    // façon synchrone avant tout await — donc le JS n'est jamais peint, et la
    // cause est le compositeur, pas le chargement des assets.
    //
    // La variable n'est lue qu'au démarrage de WebKitGTK, d'où sa position
    // avant `run()`. On respecte une valeur déjà fournie par l'utilisateur.
    // Sans effet sur Windows et macOS.
    #[cfg(target_os = "linux")]
    unsafe {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }

    client_lib::run()
}
