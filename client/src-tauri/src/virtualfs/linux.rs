// Linux backend: no OS-level "online-only file" concept exists (unlike NTFS
// reparse points or macOS File Provider), so on Linux the standard approach
// (used by Dropbox/Nextcloud on Linux) is to host the sync folder yourself
// as a FUSE filesystem: real files are just passed through, and "online-only"
// placeholders are served from an in-memory (or file-backed) metadata table
// until the sync engine hydrates them.
//
// This is a real, compiling skeleton (`fuser` 0.18.0,
// https://docs.rs/fuser/0.18.0) proving the wiring, not a production FUSE fs:
// - only `lookup`/`getattr`/`read` are implemented (enough to prove the
//   read -> hydrate callback path)
// - single flat directory, fixed inode scheme, no write/create/rename support
// - unverified on this Windows host beyond "this is structurally sound Rust
//   that would compile/link against libfuse on a real Linux box" — fuser and
//   libfuse are not available to build or run here.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyEntry, Request,
};

use super::{Result, VirtualFilesystem};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

/// Metadata for one placeholder entry: path -> {remote_id, size, hydrated}.
#[derive(Clone)]
struct PlaceholderMeta {
    ino: u64,
    remote_id: String,
    size: u64,
    hydrated: bool,
    /// Dummy local bytes once "hydrated" (no real download client exists yet).
    data: Vec<u8>,
}

/// Shared in-memory table, keyed by file name within the single mounted directory.
#[derive(Default, Clone)]
pub struct PlaceholderTable(Arc<Mutex<HashMap<String, PlaceholderMeta>>>);

impl PlaceholderTable {
    fn insert(&self, name: String, remote_id: String, size: u64, ino: u64) {
        self.0.lock().unwrap().insert(
            name,
            PlaceholderMeta {
                ino,
                remote_id,
                size,
                hydrated: false,
                data: Vec::new(),
            },
        );
    }

    fn get_by_ino(&self, ino: u64) -> Option<(String, PlaceholderMeta)> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|(_, m)| m.ino == ino)
            .map(|(name, m)| (name.clone(), m.clone()))
    }
}

/// Minimal FUSE filesystem exposing placeholder files. `hydrate_cb` is called
/// (stubbed, see [VirtualFilesystem::hydrate]) the first time a placeholder's
/// content is actually read.
pub struct PlasteFuseFs {
    table: PlaceholderTable,
    hydrate_cb: Arc<dyn Fn(&Path) -> Result<Vec<u8>> + Send + Sync>,
}

impl PlasteFuseFs {
    pub fn new(
        table: PlaceholderTable,
        hydrate_cb: Arc<dyn Fn(&Path) -> Result<Vec<u8>> + Send + Sync>,
    ) -> Self {
        Self { table, hydrate_cb }
    }

    fn attr_for(ino: u64, size: u64, kind: FileType) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: (size + 511) / 512,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm: if kind == FileType::Directory {
                0o755
            } else {
                0o644
            },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

impl Filesystem for PlasteFuseFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent.0 != ROOT_INO {
            reply.error(Errno::ENOENT);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.table.0.lock().unwrap().get(name) {
            Some(meta) => reply.entry(
                &TTL,
                &Self::attr_for(meta.ino, meta.size, FileType::RegularFile),
                Generation(0),
            ),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino.0 == ROOT_INO {
            reply.attr(&TTL, &Self::attr_for(ROOT_INO, 0, FileType::Directory));
            return;
        }
        match self.table.get_by_ino(ino.0) {
            Some((_, meta)) => reply.attr(&TTL, &Self::attr_for(ino.0, meta.size, FileType::RegularFile)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let Some((name, meta)) = self.table.get_by_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        // First read of a placeholder triggers hydration (stubbed: no real
        // Plaste download client exists yet, see `VirtualFilesystem::hydrate`).
        let data = if meta.hydrated {
            meta.data
        } else {
            let path = PathBuf::from("/").join(&name);
            let bytes = (self.hydrate_cb)(&path).unwrap_or_default();
            let mut table = self.table.0.lock().unwrap();
            if let Some(entry) = table.get_mut(&name) {
                entry.hydrated = true;
                entry.data = bytes.clone();
            }
            bytes
        };

        let start = offset as usize;
        let end = (start + size as usize).min(data.len());
        reply.data(data.get(start..end).unwrap_or(&[]));
    }
}

pub struct LinuxVfs {
    table: PlaceholderTable,
    next_ino: Mutex<u64>,
}

impl LinuxVfs {
    pub fn new() -> Self {
        Self {
            table: PlaceholderTable::default(),
            next_ino: Mutex::new(2), // 1 is reserved for the mount root
        }
    }
}

impl VirtualFilesystem for LinuxVfs {
    fn register_sync_root(&self, local_path: &Path, _display_name: &str) -> Result<()> {
        // A real implementation spawns `fuser::mount2(PlasteFuseFs::new(...), local_path, &opts)`
        // on a background thread and keeps the `BackgroundSession` alive for
        // the app's lifetime; omitted here since there's no sync engine yet
        // to drive `hydrate_cb` with real data.
        std::fs::create_dir_all(local_path).map_err(|e| e.to_string())
    }

    fn create_placeholder(&self, path: &Path, remote_size: u64, remote_id: &str) -> Result<()> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("path has no file name")?
            .to_string();
        let ino = {
            let mut next = self.next_ino.lock().unwrap();
            let ino = *next;
            *next += 1;
            ino
        };
        self.table.insert(name, remote_id.to_string(), remote_size, ino);
        Ok(())
    }

    fn hydrate(&self, _path: &Path) -> Result<()> {
        // Stub: no real Plaste download client yet. A real engine would fetch
        // bytes here; the FUSE `read` handler above calls into this same
        // trait method (via `hydrate_cb`) when it needs content.
        Ok(())
    }

    fn dehydrate(&self, path: &Path) -> Result<()> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("path has no file name")?;
        if let Some(meta) = self.table.0.lock().unwrap().get_mut(name) {
            meta.hydrated = false;
            meta.data.clear();
        }
        Ok(())
    }
}
