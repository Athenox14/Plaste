// Windows backend: Cloud Filter API (the API OneDrive/Dropbox use), via the
// `cloud-filter` crate (v0.0.6, https://docs.rs/cloud-filter/0.0.6).
//
// API mapping notes (the crate's shape doesn't line up 1:1 with our trait):
// - `register_sync_root` -> `SyncRootIdBuilder::new(provider).build()` then
//   `SyncRootId::register(SyncRootInfo)`. The real API also *requires* an
//   active `Session::connect(path, filter)` with a `SyncFilter` impl (the
//   callback object the OS calls into for fetch_data/dehydrate/etc) for the
//   shell to actually drive hydration through Explorer. We don't have a real
//   sync engine yet, so we register the root but do not keep a live
//   connection open here — a future sync engine owns that lifetime.
// - `create_placeholder` -> `PlaceholderFile::new(relative_path).metadata(..).create(parent_dir)`.
//   This crate call needs a *relative* file name plus the *parent directory*
//   path (not the full target path) — we split `path` into those two pieces.
// - `hydrate` -> `Placeholder::open(path)` then `.hydrate(..)` (CfHydratePlaceholder).
//   This forces population of the full byte range immediately; real on-demand
//   hydration would instead happen automatically when the OS calls
//   `SyncFilter::fetch_data` on file open, which requires the connected
//   session mentioned above.
// - `dehydrate` -> `Placeholder::open(path)` then `.convert_to_placeholder(ConvertOptions::default().dehydrate(), None)`.

use std::path::Path;

use cloud_filter::{
    metadata::Metadata,
    placeholder::{ConvertOptions, OpenOptions},
    placeholder_file::PlaceholderFile,
    root::{HydrationPolicy, HydrationType, PopulationType, SyncRootIdBuilder, SyncRootInfo},
};

use super::{Result, VirtualFilesystem};

pub struct WindowsVfs;

impl WindowsVfs {
    pub fn new() -> Self {
        Self
    }
}

impl VirtualFilesystem for WindowsVfs {
    fn register_sync_root(&self, local_path: &Path, display_name: &str) -> Result<()> {
        let sync_root_id = SyncRootIdBuilder::new("Plaste").build();

        let info = SyncRootInfo::default()
            .with_display_name(display_name)
            .with_path(local_path)
            .map_err(|e| e.to_string())?
            .with_hydration_type(HydrationType::Full)
            .with_hydration_policy(HydrationPolicy::ValidationRequired)
            .with_population_type(PopulationType::Full)
            .with_allow_pinning(true);

        sync_root_id.register(info).map_err(|e| e.to_string())
        // ponytail: no live Session::connect(..) held here (needs a real
        // SyncFilter impl backed by an actual sync engine); add once one exists.
    }

    fn create_placeholder(&self, path: &Path, remote_size: u64, remote_id: &str) -> Result<()> {
        let parent = path.parent().ok_or("path has no parent directory")?;
        let file_name = path.file_name().ok_or("path has no file name")?;

        PlaceholderFile::new(file_name)
            .metadata(Metadata::file().size(remote_size))
            .mark_in_sync()
            .blob(remote_id.as_bytes().to_vec())
            .create::<&Path>(parent)
            .map(|_usn| ())
            .map_err(|e| e.to_string())
    }

    fn hydrate(&self, path: &Path) -> Result<()> {
        let mut placeholder = OpenOptions::new()
            .write_access()
            .open(path)
            .map_err(|e| e.to_string())?;
        placeholder.hydrate(..).map_err(|e| e.to_string())
    }

    fn dehydrate(&self, path: &Path) -> Result<()> {
        let mut placeholder = OpenOptions::new()
            .write_access()
            .open(path)
            .map_err(|e| e.to_string())?;
        placeholder
            .convert_to_placeholder(ConvertOptions::default().dehydrate(), None)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}
