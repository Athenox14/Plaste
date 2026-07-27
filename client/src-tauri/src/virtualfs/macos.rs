// macOS backend: HONEST STUB, not a fake implementation.
//
// The real "Files On Demand" equivalent on macOS is Apple's File Provider
// framework, specifically `NSFileProviderReplicatedExtension`
// (https://developer.apple.com/documentation/fileprovider/nsfileproviderreplicatedextension).
// This CANNOT be implemented in pure Rust and cannot be built or tested from
// this Windows machine at all, because:
//
// 1. `NSFileProviderReplicatedExtension` is a class that must be *subclassed*
//    and registered as a separate `.appex` (App Extension) target inside an
//    Xcode project — Apple requires the extension to ship as its own signed
//    bundle embedded in the host app, wired up via Xcode project settings
//    (entitlements, extension point identifier in its Info.plist, an App
//    Group shared with the host app), none of which `cargo build` produces.
// 2. The subclass itself is necessarily written in Swift or Objective-C: it's
//    the piece macOS instantiates directly via the Objective-C runtime, and
//    while individual method bodies could theoretically call into Rust (e.g.
//    a Rust static library linked into the extension, or an XPC connection
//    back to the host app for the actual sync logic), the extension's class
//    definition, its Info.plist registration, and its entitlements are an
//    Xcode-managed artifact, not something this Cargo workspace produces.
// 3. `objc2-file-provider` (added as a `[target.'cfg(target_os = "macos")'.dependencies]`
//    crate here) gives Rust-side bindings to the File Provider *types*
//    (`NSFileProviderItem`, `NSFileProviderManager`, domain registration,
//    `NSFileProviderReplicatedExtension`'s protocol methods as a trait-like
//    surface) — genuinely useful for the *host app* side (e.g. calling
//    `NSFileProviderManager` to register a domain, signal enumeration
//    changes) and potentially for implementing the extension's business
//    logic in Rust behind an FFI boundary. But the extension's outermost
//    class shell, App Extension bundle, and Xcode target registration are
//    not achievable from a `cargo build` alone.
//
// Given all that, this module implements the trait honestly: it compiles and
// documents the real integration path, and every method returns a clear
// error rather than pretending to work.

use std::path::Path;

use super::{Result, VirtualFilesystem};

pub struct MacVfs;

impl MacVfs {
    pub fn new() -> Self {
        Self
    }
}

const UNIMPLEMENTED: &str =
    "requires native Swift File Provider extension, see module docs (client/src-tauri/src/virtualfs/macos.rs)";

impl VirtualFilesystem for MacVfs {
    fn register_sync_root(&self, _local_path: &Path, _display_name: &str) -> Result<()> {
        Err(UNIMPLEMENTED.to_string())
    }

    fn create_placeholder(&self, _path: &Path, _remote_size: u64, _remote_id: &str) -> Result<()> {
        Err(UNIMPLEMENTED.to_string())
    }

    fn hydrate(&self, _path: &Path) -> Result<()> {
        Err(UNIMPLEMENTED.to_string())
    }

    fn dehydrate(&self, _path: &Path) -> Result<()> {
        Err(UNIMPLEMENTED.to_string())
    }
}
