// Selective-sync config skeleton: a JSON file listing server-side folders and
// whether each is synced locally or left "online-only" (placeholder only —
// no actual hydration/virtual-filesystem support here).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncFolder {
    pub path: String,
    pub synced: bool,
}

fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("sync_folders.json"))
}

fn load(app: &AppHandle) -> Result<Vec<SyncFolder>, String> {
    let path = config_path(app)?;
    if !path.exists() {
        // Seed with a couple of placeholder server folders on first run.
        let defaults = vec![
            SyncFolder { path: "/Documents".into(), synced: true },
            SyncFolder { path: "/Photos".into(), synced: false },
            SyncFolder { path: "/Projects".into(), synced: false },
        ];
        save(app, &defaults)?;
        return Ok(defaults);
    }
    let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

fn save(app: &AppHandle, folders: &[SyncFolder]) -> Result<(), String> {
    let path = config_path(app)?;
    let data = serde_json::to_string_pretty(folders).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_sync_folders(app: AppHandle) -> Result<Vec<SyncFolder>, String> {
    load(&app)
}

#[tauri::command]
pub fn toggle_folder_sync(app: AppHandle, path: String) -> Result<Vec<SyncFolder>, String> {
    let mut folders = load(&app)?;
    match folders.iter_mut().find(|f| f.path == path) {
        Some(f) => f.synced = !f.synced,
        None => return Err(format!("unknown folder: {path}")),
    }
    save(&app, &folders)?;
    Ok(folders)
}
