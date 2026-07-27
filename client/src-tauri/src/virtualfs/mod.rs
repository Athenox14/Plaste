// Virtual-files / online-only ("Files On Demand" / Smart Sync style) scaffolding.
//
// This is a platform integration SKELETON only: it defines the common trait a
// future sync engine would implement/drive against, plus a real-but-minimal
// per-OS backend. None of these talk to an actual Plaste server yet — there is
// no download client, so `hydrate` on every platform is necessarily a stub or
// dummy-bytes placeholder for now.

use std::path::Path;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

pub type Result<T> = std::result::Result<T, String>;

/// Common surface a per-OS "files on demand" backend must implement.
///
/// - `register_sync_root`: tell the OS shell that `local_path` is a synced
///   folder (Explorer/Finder/file manager integration, icon overlays, etc).
/// - `create_placeholder`: create an online-only file entry that appears in
///   the filesystem but has no local content yet.
/// - `hydrate`: download the real content on demand (e.g. user opened the file).
/// - `dehydrate`: free local disk space, turning a full file back into a placeholder.
pub trait VirtualFilesystem: Send + Sync {
    fn register_sync_root(&self, local_path: &Path, display_name: &str) -> Result<()>;
    fn create_placeholder(&self, path: &Path, remote_size: u64, remote_id: &str) -> Result<()>;
    fn hydrate(&self, path: &Path) -> Result<()>;
    fn dehydrate(&self, path: &Path) -> Result<()>;
}

/// Returns the platform-appropriate [VirtualFilesystem] backend.
pub fn platform_vfs() -> Box<dyn VirtualFilesystem> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsVfs::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxVfs::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacVfs::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        compile_error!("virtualfs: unsupported target OS");
    }
}

/// Whether this platform's virtual-filesystem backend actually works, as opposed to
/// `MacVfs`'s honest stub (every method errors — see `macos.rs` docs). The desktop app
/// uses this to surface a clear "not supported here" message instead of silently no-op'ing.
#[cfg(target_os = "macos")]
pub fn platform_supports_virtual_files() -> bool {
    false
}
#[cfg(not(target_os = "macos"))]
pub fn platform_supports_virtual_files() -> bool {
    true
}

#[tauri::command]
pub fn check_virtual_files_support() -> bool {
    platform_supports_virtual_files()
}

#[tauri::command]
pub fn register_sync_root(local_path: String, display_name: String) -> Result<()> {
    platform_vfs().register_sync_root(Path::new(&local_path), &display_name)
}

#[tauri::command]
pub fn create_placeholder(path: String, remote_size: u64, remote_id: String) -> Result<()> {
    platform_vfs().create_placeholder(Path::new(&path), remote_size, &remote_id)
}
