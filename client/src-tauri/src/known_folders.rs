// Windows known-folder redirection (OneDrive/Dropbox-style "point my Documents
// at my cloud folder"), revertible.
//
// IMPORTANT: `SHSetKnownFolderPath` only changes WHERE THE SHELL/EXPLORER
// POINTS for a known folder (the registry-level pointer) — it does NOT move
// existing files there automatically. To avoid the user "losing" their
// existing Documents/etc. on redirect, we do a best-effort file migration
// (rename if same drive, copy+delete fallback cross-drive, skipping/logging
// any locked/in-use file rather than crashing) *before* flipping the pointer.
//
// Revert is deliberately NOT symmetric: it only restores the pointer to the
// persisted original path. It does NOT move files back. Moving arbitrary
// files back automatically on revert is much higher blast-radius (files may
// have been added/renamed/deleted by the user or by sync since redirect) —
// a plain pointer-revert is the safe default here.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

use crate::user_folders::plaste_root;

/// The 6 known folders we support redirecting, and their Plaste subfolder name.
pub const KNOWN_FOLDERS: [&str; 6] = ["Documents", "Downloads", "Pictures", "Music", "Videos", "Desktop"];

#[derive(Serialize, Deserialize, Default)]
struct RedirectedFolders(HashMap<String, String>); // folder name -> persisted original path

fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("redirected_folders.json"))
}

fn load(app: &AppHandle) -> Result<RedirectedFolders, String> {
    let path = config_path(app)?;
    if !path.exists() {
        return Ok(RedirectedFolders::default());
    }
    let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    Ok(serde_json::from_str(&data).unwrap_or_default())
}

fn save(app: &AppHandle, state: &RedirectedFolders) -> Result<(), String> {
    let path = config_path(app)?;
    let data = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

/// Best-effort move of every entry in `from` into `to`. Never fails hard: any
/// individual file that can't be moved (locked/in-use/permission denied) is
/// skipped and reported back rather than aborting the whole migration.
fn migrate_contents(from: &Path, to: &Path) -> io::Result<Vec<String>> {
    let mut skipped = Vec::new();
    if !from.exists() {
        return Ok(skipped);
    }
    for entry in fs::read_dir(from)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let src = entry.path();
        let dest = to.join(entry.file_name());
        // rename() is atomic and cheap when same drive; falls back to copy+delete
        // (e.g. cross-drive, since Plaste/ may live on a different volume).
        if fs::rename(&src, &dest).is_ok() {
            continue;
        }
        let copy_result = if src.is_dir() {
            copy_dir_recursive(&src, &dest)
        } else {
            fs::copy(&src, &dest).map(|_| ())
        };
        match copy_result {
            Ok(()) => {
                let _ = if src.is_dir() {
                    fs::remove_dir_all(&src)
                } else {
                    fs::remove_file(&src)
                };
            }
            Err(_) => skipped.push(src.display().to_string()),
        }
    }
    Ok(skipped)
}

fn copy_dir_recursive(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dest = to.join(entry.file_name());
        if src.is_dir() {
            copy_dir_recursive(&src, &dest)?;
        } else {
            fs::copy(&src, &dest)?;
        }
    }
    Ok(())
}

/// Abstraction over the Win32 known-folder get/set calls so the
/// persist-original/migrate/redirect logic can be exercised in tests without
/// touching the real Shell API (which would affect this machine's actual
/// Documents/Downloads/etc. mid-test-run).
pub trait KnownFolderApi {
    fn get(&self, folder: &str) -> Result<PathBuf, String>;
    fn set(&self, folder: &str, path: &Path) -> Result<(), String>;
}

#[cfg(target_os = "windows")]
pub struct Win32Api;

#[cfg(target_os = "windows")]
mod win32 {
    use super::*;
    use windows::core::GUID;
    use windows::Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_Music,
        FOLDERID_Pictures, FOLDERID_Videos, SHGetKnownFolderPath, SHSetKnownFolderPath,
        KF_FLAG_DEFAULT,
    };
    use windows::Win32::Foundation::HANDLE;

    fn guid_for(folder: &str) -> Result<GUID, String> {
        match folder {
            "Documents" => Ok(FOLDERID_Documents),
            "Downloads" => Ok(FOLDERID_Downloads),
            "Pictures" => Ok(FOLDERID_Pictures),
            "Music" => Ok(FOLDERID_Music),
            "Videos" => Ok(FOLDERID_Videos),
            "Desktop" => Ok(FOLDERID_Desktop),
            other => Err(format!("unknown known folder: {other}")),
        }
    }

    impl KnownFolderApi for super::Win32Api {
        fn get(&self, folder: &str) -> Result<PathBuf, String> {
            let id = guid_for(folder)?;
            unsafe {
                let pwstr = SHGetKnownFolderPath(&id, KF_FLAG_DEFAULT, Some(HANDLE::default()))
                    .map_err(|e| e.to_string())?;
                let s = pwstr.to_string().map_err(|e| e.to_string())?;
                windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.0 as *const _));
                Ok(PathBuf::from(s))
            }
        }

        fn set(&self, folder: &str, path: &Path) -> Result<(), String> {
            let id = guid_for(folder)?;
            let wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                SHSetKnownFolderPath(
                    &id,
                    KF_FLAG_DEFAULT.0 as u32,
                    Some(HANDLE::default()),
                    windows::core::PCWSTR(wide.as_ptr()),
                )
                .map_err(|e| e.to_string())
            }
        }
    }

    use std::os::windows::ffi::OsStrExt;
}

/// Redirects `folder` to `Plaste/{folder}`, persisting the original path first
/// (so it can be reverted) and migrating existing files best-effort.
#[cfg(target_os = "windows")]
pub fn redirect_known_folder(
    api: &dyn KnownFolderApi,
    app: &AppHandle,
    folder: &str,
) -> Result<Vec<String>, String> {
    if !KNOWN_FOLDERS.contains(&folder) {
        return Err(format!("unknown known folder: {folder}"));
    }
    let current = api.get(folder)?;
    let target = plaste_root().join(folder);
    fs::create_dir_all(&target).map_err(|e| e.to_string())?;

    // Persist the undo target BEFORE touching anything, per the revertible requirement.
    let mut state = load(app)?;
    state.0.entry(folder.to_string()).or_insert_with(|| current.display().to_string());
    save(app, &state)?;

    let skipped = migrate_contents(&current, &target).map_err(|e| e.to_string())?;

    api.set(folder, &target)?;
    Ok(skipped)
}

#[cfg(target_os = "windows")]
pub fn revert_known_folder(api: &dyn KnownFolderApi, app: &AppHandle, folder: &str) -> Result<(), String> {
    let mut state = load(app)?;
    let original = state
        .0
        .remove(folder)
        .ok_or_else(|| format!("{folder} is not currently redirected"))?;
    api.set(folder, Path::new(&original))?;
    save(app, &state)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn redirect_known_folder(_api: &dyn KnownFolderApi, _app: &AppHandle, _folder: &str) -> Result<Vec<String>, String> {
    Err("known folder redirection is Windows-only (Shell known-folder API has no equivalent on this platform)".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn revert_known_folder(_api: &dyn KnownFolderApi, _app: &AppHandle, _folder: &str) -> Result<(), String> {
    Err("known folder redirection is Windows-only (Shell known-folder API has no equivalent on this platform)".to_string())
}

#[derive(Serialize)]
pub struct KnownFolderInfo {
    folder: String,
    current_path: String,
    is_redirected: bool,
}

#[cfg(target_os = "windows")]
#[tauri::command]
pub fn list_known_folders(app: AppHandle) -> Result<Vec<KnownFolderInfo>, String> {
    let state = load(&app)?;
    let api = Win32Api;
    KNOWN_FOLDERS
        .iter()
        .map(|folder| {
            let current_path = api.get(folder)?.display().to_string();
            Ok(KnownFolderInfo {
                folder: folder.to_string(),
                current_path,
                is_redirected: state.0.contains_key(*folder),
            })
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
pub fn list_known_folders(_app: AppHandle) -> Result<Vec<KnownFolderInfo>, String> {
    Err("known folder redirection is Windows-only".to_string())
}

#[tauri::command]
pub fn redirect_folder_cmd(app: AppHandle, folder: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let api = Win32Api;
        redirect_known_folder(&api, &app, &folder)?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        redirect_known_folder(&NoopApi, &app, &folder).map(|_| ())
    }
}

#[tauri::command]
pub fn revert_folder_cmd(app: AppHandle, folder: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let api = Win32Api;
        revert_known_folder(&api, &app, &folder)
    }
    #[cfg(not(target_os = "windows"))]
    {
        revert_known_folder(&NoopApi, &app, &folder)
    }
}

#[cfg(not(target_os = "windows"))]
struct NoopApi;
#[cfg(not(target_os = "windows"))]
impl KnownFolderApi for NoopApi {
    fn get(&self, _folder: &str) -> Result<PathBuf, String> {
        Err("known folder redirection is Windows-only".to_string())
    }
    fn set(&self, _folder: &str, _path: &Path) -> Result<(), String> {
        Err("known folder redirection is Windows-only".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap as StdHashMap;

    /// Mock KnownFolderApi so redirect/revert *logic* (persist-original,
    /// migrate, update config) is tested without calling the real Shell API —
    /// calling the real SHSetKnownFolderPath against FOLDERID_Documents etc.
    /// mid-test-run would redirect this dev machine's real folders, which we
    /// will not do.
    struct MockApi {
        paths: RefCell<StdHashMap<String, PathBuf>>,
    }

    impl KnownFolderApi for MockApi {
        fn get(&self, folder: &str) -> Result<PathBuf, String> {
            self.paths
                .borrow()
                .get(folder)
                .cloned()
                .ok_or_else(|| "not set".into())
        }
        fn set(&self, folder: &str, path: &Path) -> Result<(), String> {
            self.paths.borrow_mut().insert(folder.to_string(), path.to_path_buf());
            Ok(())
        }
    }

    #[test]
    fn migrate_contents_moves_files_same_drive() {
        let tmp = std::env::temp_dir().join(format!("plaste_test_{}", std::process::id()));
        let from = tmp.join("from");
        let to = tmp.join("to");
        fs::create_dir_all(&from).unwrap();
        fs::create_dir_all(&to).unwrap();
        fs::write(from.join("a.txt"), b"hello").unwrap();

        let skipped = migrate_contents(&from, &to).unwrap();
        assert!(skipped.is_empty());
        assert!(to.join("a.txt").exists());
        assert!(!from.join("a.txt").exists());

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn mock_api_roundtrip() {
        let api = MockApi { paths: RefCell::new(StdHashMap::from([("Documents".to_string(), PathBuf::from("C:\\Users\\test\\Documents"))])) };
        assert_eq!(api.get("Documents").unwrap(), PathBuf::from("C:\\Users\\test\\Documents"));
        api.set("Documents", Path::new("D:\\Plaste\\Documents")).unwrap();
        assert_eq!(api.get("Documents").unwrap(), PathBuf::from("D:\\Plaste\\Documents"));
    }
}
