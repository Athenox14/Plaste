use hiqlite::params;

use crate::storage::ChunkStore;

struct RefcountRow {
    refcount: i64,
}
impl From<&mut hiqlite::Row<'_>> for RefcountRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self {
            refcount: row.get("refcount"),
        }
    }
}

/// Releases one reference to each chunk in `manifest` (call once per permanently-deleted
/// file_versions row). Decrements `chunks.refcount`; when it reaches 0, deletes the DB row
/// and the on-disk blob.
pub async fn release_manifest(db: &hiqlite::Client, storage: &ChunkStore, manifest: &[String]) {
    for hash in manifest {
        let row: Result<RefcountRow, _> = db
            .execute_returning_map_one(
                "UPDATE chunks SET refcount = refcount - 1 WHERE hash = $1 RETURNING refcount",
                params!(hash),
            )
            .await;
        let Ok(row) = row else { continue };
        if row.refcount <= 0 {
            let _ = db
                .execute("DELETE FROM chunks WHERE hash = $1", params!(hash))
                .await;
            let _ = storage.delete_chunk(hash).await;
        }
    }
}

struct HashRow {
    hash: String,
}
impl From<&mut hiqlite::Row<'_>> for HashRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { hash: row.get("hash") }
    }
}

/// Defensive periodic sweep (mimics `tiering::run_tiering_sweep` / `retention::purge_expired_trash`'s
/// shape): `release_manifest` normally deletes a chunk's row+blob the instant its refcount hits 0,
/// so this should find nothing in the common case. It exists to catch anything that slipped through
/// (crash between the UPDATE and the delete, manual DB edits, etc.) — a backstop, not the primary
/// cleanup path. Returns the count of chunk rows/blobs cleaned up.
///
/// Note: does NOT also cross-reference on-disk blobs with no `chunks` row at all (the "truly
/// orphaned blob" case). `ChunkStore` doesn't expose a `list`/`lister` over its `opendal::Operator`
/// today, and adding one means editing storage.rs, which is off-limits here (owned by the
/// crypto/key-rotation work). The refcount-based sweep above is the primary mechanism per the task
/// spec; add a `ChunkStore::list_all_hashes` (fs-only is fine, per spec) later if this is needed.
pub async fn sweep_orphaned_chunks(db: &hiqlite::Client, storage: &ChunkStore) -> std::io::Result<u64> {
    let rows: Vec<HashRow> = db
        .query_map("SELECT hash FROM chunks WHERE refcount <= 0", hiqlite::params!())
        .await
        .map_err(std::io::Error::other)?;

    let mut cleaned = 0u64;
    for row in rows {
        let _ = db
            .execute("DELETE FROM chunks WHERE hash = $1", hiqlite::params!(row.hash.clone()))
            .await;
        let _ = storage.delete_chunk(&row.hash).await;
        cleaned += 1;
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ChunkStore;

    struct RcRow {
        refcount: i64,
    }
    impl From<&mut hiqlite::Row<'_>> for RcRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self {
                refcount: row.get("refcount"),
            }
        }
    }

    async fn setup() -> (hiqlite::Client, ChunkStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        let storage_dir = dir.path().join("chunks");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();
        (db, ChunkStore::new(storage_dir), dir)
    }

    /// Inserts a chunk row (or bumps refcount) exactly like files.rs's upload handler does.
    async fn bump_refcount(db: &hiqlite::Client, hash: &str, size: i64) {
        let existing: Option<RcRow> = db
            .query_map_optional("SELECT refcount FROM chunks WHERE hash = $1", params!(hash))
            .await
            .unwrap();
        if existing.is_some() {
            db.execute("UPDATE chunks SET refcount = refcount + 1 WHERE hash = $1", params!(hash))
                .await
                .unwrap();
        } else {
            db.execute(
                "INSERT INTO chunks (hash, size, refcount) VALUES ($1, $2, 1)",
                params!(hash, size),
            )
            .await
            .unwrap();
        }
    }

    async fn refcount(db: &hiqlite::Client, hash: &str) -> Option<i64> {
        let row: Option<RcRow> = db
            .query_map_optional("SELECT refcount FROM chunks WHERE hash = $1", params!(hash))
            .await
            .unwrap();
        row.map(|r| r.refcount)
    }

    #[tokio::test]
    async fn purge_deletes_chunk_row_and_blob_when_refcount_hits_zero() {
        let (db, storage, _dir) = setup().await;
        let (manifest, _size) = storage.write(b"hello world, this is chunk data").await.unwrap();
        for h in &manifest {
            bump_refcount(&db, h, 32).await;
        }
        for h in &manifest {
            assert!(storage.chunk_exists(h).await.unwrap());
        }

        release_manifest(&db, &storage, &manifest).await;

        for h in &manifest {
            assert_eq!(refcount(&db, h).await, None, "chunk row should be gone");
            assert!(!storage.chunk_exists(h).await.unwrap(), "blob should be deleted");
        }
    }

    #[tokio::test]
    async fn shared_chunk_survives_until_last_reference_released() {
        let (db, storage, _dir) = setup().await;
        let (manifest, _size) = storage.write(b"shared content across two versions").await.unwrap();

        // Two manifest-references (e.g. original version + a restore reusing it):
        // each creation increments refcount once, per the upload/restore invariant.
        for h in &manifest {
            bump_refcount(&db, h, 32).await; // version 1
        }
        for h in &manifest {
            bump_refcount(&db, h, 32).await; // version 2 (restore)
        }

        // Purge version 1's reference: chunk must survive.
        release_manifest(&db, &storage, &manifest).await;
        for h in &manifest {
            assert!(refcount(&db, h).await.unwrap_or(0) >= 1, "chunk should still be referenced");
            assert!(storage.chunk_exists(h).await.unwrap(), "blob should still be readable");
        }

        // Purge version 2's reference: now it should be gone.
        release_manifest(&db, &storage, &manifest).await;
        for h in &manifest {
            assert_eq!(refcount(&db, h).await, None);
            assert!(!storage.chunk_exists(h).await.unwrap());
        }
    }

    #[tokio::test]
    async fn sweep_cleans_up_zero_refcount_row_and_blob() {
        let (db, storage, _dir) = setup().await;
        let (manifest, size) = storage.write(b"orphaned chunk that slipped through").await.unwrap();
        let hash = &manifest[0];
        // Insert directly with refcount 0, bypassing the normal write path (simulates a
        // crash between decrement and blob-delete, or a manual DB edit).
        db.execute(
            "INSERT INTO chunks (hash, size, refcount) VALUES ($1, $2, 0)",
            params!(hash, size),
        )
        .await
        .unwrap();
        assert!(storage.chunk_exists(hash).await.unwrap());

        let cleaned = sweep_orphaned_chunks(&db, &storage).await.unwrap();

        assert_eq!(cleaned, 1);
        assert_eq!(refcount(&db, hash).await, None, "row should be gone");
        assert!(!storage.chunk_exists(hash).await.unwrap(), "blob should be gone");
    }

    #[tokio::test]
    async fn sweep_does_not_touch_referenced_chunks() {
        let (db, storage, _dir) = setup().await;
        let (manifest, _size) = storage.write(b"still referenced chunk data").await.unwrap();
        let hash = &manifest[0];
        bump_refcount(&db, hash, 32).await;

        let cleaned = sweep_orphaned_chunks(&db, &storage).await.unwrap();

        assert_eq!(cleaned, 0);
        assert_eq!(refcount(&db, hash).await, Some(1));
        assert!(storage.chunk_exists(hash).await.unwrap());
    }
}
