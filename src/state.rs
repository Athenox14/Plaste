use std::path::PathBuf;
use std::sync::Arc;

use crate::fulltext::FullTextIndex;
use crate::storage::ChunkStore;

#[derive(Clone)]
pub struct AppState {
    pub db: hiqlite::Client,
    pub storage: Arc<ChunkStore>,
    pub chunks_dir: PathBuf,
    pub fts: Arc<FullTextIndex>,
}
