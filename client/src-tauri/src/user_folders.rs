// Creates the `~/Plaste/` folder tree mirroring the standard Windows user
// folders. Uses `dirs::home_dir()` for a reliable cross-platform home lookup
// instead of hand-rolling %USERPROFILE%/$HOME env reads.

use std::io;
use std::path::PathBuf;

pub const SUBFOLDERS: [&str; 6] = ["Documents", "Downloads", "Pictures", "Music", "Videos", "Desktop"];

pub fn plaste_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Plaste")
}

pub fn ensure_plaste_folders() -> io::Result<()> {
    let root = plaste_root();
    std::fs::create_dir_all(&root)?;
    for sub in SUBFOLDERS {
        std::fs::create_dir_all(root.join(sub))?;
    }
    Ok(())
}

#[tauri::command]
pub fn ensure_plaste_folders_cmd() -> Result<(), String> {
    ensure_plaste_folders().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaste_root_ends_with_plaste() {
        assert!(plaste_root().ends_with("Plaste"));
    }
}
