mod account;
mod api_client;
mod known_folders;
mod power;
mod remote;
mod sync_config;
mod sync_engine;
mod transfer;
mod user_folders;
mod virtualfs;
mod watcher;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // Single-instance must be registered before other plugins (desktop only).
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // A second launch was attempted: focus the existing main window instead.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }));
    }

    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_store::Builder::new().build())
        // Sélecteur de fichiers (téléverser) / d'emplacement (télécharger) natif.
        .plugin(tauri_plugin_dialog::init())
        // Copier un lien de partage : l'API clipboard du webview est souvent bloquée.
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // Tray icon with a minimal show/quit menu. Left-click shows the window;
            // this is the "system-tray-accessible small window" entry point.
            let show_item = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        button_state: tauri::tray::MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        // Closing the window hides it to tray instead of quitting the app
        // (ponytail: no "really quit" confirmation, add if users complain about
        // a vanishing window with no obvious way back besides the tray icon).
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            watcher::start_watching,
            sync_config::list_sync_folders,
            sync_config::toggle_folder_sync,
            virtualfs::register_sync_root,
            virtualfs::create_placeholder,
            virtualfs::check_virtual_files_support,
            power::get_power_status,
            sync_engine::test_connection,
            sync_engine::sync_file_delta_cmd,
            sync_engine::upload_file_dedup_aware_cmd,
            user_folders::ensure_plaste_folders_cmd,
            known_folders::list_known_folders,
            known_folders::redirect_folder_cmd,
            known_folders::revert_folder_cmd,
            // Configuration du serveur + jeton (trousseau système)
            account::server_get,
            account::server_set,
            account::token_get,
            account::token_set,
            account::token_clear,
            transfer::server_probe,
            // Transferts en flux
            transfer::upload_stream,
            transfer::download_stream,
            transfer::transfer_cancel,
            // Parcours / partage
            remote::remote_list,
            remote::remote_create_folder,
            remote::remote_update_file,
            remote::remote_delete_file,
            remote::share_create,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
