//! Automatic hot/cold chunk tiering ("Tiering hot/cold automatique").
//!
//! The actual tiering logic (tier-aware reads, sweep) lives on `ChunkStore`
//! (`storage.rs`) since that's the type every caller already holds — see
//! `ChunkStore::with_tiering`, `ChunkStore::run_tiering_sweep`. This module only
//! owns the tiering-specific schema, run separately from db.rs's shared SCHEMA
//! array (same pattern as tags.rs/comments.rs) to avoid touching code other
//! agents are editing.

/// Own schema for tiering, run separately from db.rs's SCHEMA array.
pub async fn init_schema(db: &hiqlite::Client) {
    const SCHEMA: &[&str] = &[r#"CREATE TABLE IF NOT EXISTS chunk_access (
        hash TEXT PRIMARY KEY,
        tier TEXT NOT NULL DEFAULT 'hot',
        last_accessed TEXT NOT NULL
    )"#];
    for stmt in SCHEMA {
        db.execute(*stmt, hiqlite::params!()).await.expect("tiering schema migration");
    }
}
