use aes_gcm::aead::{Aead, Generate};
use aes_gcm::Nonce;
use fastcdc::v2020::FastCDC;
use opendal::{services, Operator};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::fs;

use crate::crypto::{pad_id, unpad_id, KeyRing, KEY_ID_LEN};

const MIN: usize = 256 * 1024;
const AVG: usize = 1024 * 1024;
const MAX: usize = 4 * 1024 * 1024;
const NONCE_LEN: usize = 12;

/// Directory the master encryption key is persisted under, independent of storage backend
/// (S3-backed stores still need a local place to keep the key). `PLASTE_DATA_DIR`, default
/// `./data`.
fn master_key_dir() -> PathBuf {
    PathBuf::from(std::env::var("PLASTE_DATA_DIR").unwrap_or_else(|_| "./data".to_string()))
}

pub struct ChunkStore {
    /// The hot backend, behind a lock so `activate_backend` can swap it at runtime (mirrors
    /// how `keyring` below is locked for `rotate`). `Operator` is a cheap `Arc`-like handle,
    /// so callers lock only long enough to clone it out, never across an `.await`.
    op: Mutex<Operator>,
    /// Local-fs root, kept for callers that still want a plain path (metadata only, not
    /// meaningful when backed by S3, and stale after `activate_backend` swaps to a different
    /// backend — only used by `chunk_path`, a best-effort debug helper).
    root: Option<PathBuf>,
    /// Keyring for chunk-blob encryption at rest — supports rotation (see `crypto::KeyRing`).
    /// Mutex only because `rotate` needs to mutate it; reads/writes take a brief lock.
    keyring: Mutex<KeyRing>,
    /// Optional cold-tier backend + db handle for hot/cold chunk tiering (see `tiering.rs`).
    /// `None` for stores built without `with_tiering` (existing callers): tiering is then a
    /// no-op and behavior is identical to before.
    cold: Option<Operator>,
    db: Option<hiqlite::Client>,
}

impl ChunkStore {
    /// Local-disk backend rooted at `root` (opendal `services::Fs`).
    pub fn new_fs(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let builder = services::Fs::default().root(&root.to_string_lossy());
        let op = Operator::new(builder).expect("build fs operator").finish();
        let keyring = KeyRing::load_or_init(&master_key_dir()).expect("load keyring");
        Self { op: Mutex::new(op), root: Some(root), keyring: Mutex::new(keyring), cold: None, db: None }
    }

    /// Kept as an alias so existing call sites don't need to change.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::new_fs(root)
    }

    /// S3 (or S3-compatible, e.g. MinIO via `endpoint`) backend.
    pub fn new_s3(
        bucket: &str,
        endpoint: Option<&str>,
        region: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Self {
        let mut builder = services::S3::default()
            .bucket(bucket)
            .region(region)
            .access_key_id(access_key)
            .secret_access_key(secret_key);
        if let Some(endpoint) = endpoint {
            builder = builder.endpoint(endpoint);
        }
        let op = Operator::new(builder).expect("build s3 operator").finish();
        let keyring = KeyRing::load_or_init(&master_key_dir()).expect("load keyring");
        Self { op: Mutex::new(op), root: None, keyring: Mutex::new(keyring), cold: None, db: None }
    }

    /// Attaches a cold-tier backend + db handle, enabling hot/cold tiering (`tiering.rs`).
    /// Existing constructors (`new_fs`/`new_s3`/`from_env`) don't call this, so tiering stays
    /// a strict opt-in and every current caller is unaffected.
    pub fn with_tiering(mut self, cold: Operator, db: hiqlite::Client) -> Self {
        self.cold = Some(cold);
        self.db = Some(db);
        self
    }

    /// MVP cold tier: a second local directory (see task spec — real deployment would point
    /// this at S3 Glacier/IA via `new_s3` with different bucket/storage-class params instead).
    pub fn new_fs_cold(cold_root: impl Into<PathBuf>) -> Operator {
        let builder = services::Fs::default().root(&cold_root.into().to_string_lossy());
        Operator::new(builder).expect("build cold fs operator").finish()
    }

    /// Builds a `ChunkStore` from env vars: `PLASTE_STORAGE_BACKEND` (`"s3"` or `"fs"`,
    /// default `"fs"`). S3 needs `PLASTE_S3_BUCKET`, `PLASTE_S3_REGION`,
    /// `PLASTE_S3_ACCESS_KEY`, `PLASTE_S3_SECRET_KEY`, and optional `PLASTE_S3_ENDPOINT`.
    /// fs uses `PLASTE_DATA_DIR` (default `./data`) + `/chunks`.
    pub fn from_env() -> Self {
        let (kind, config) = Self::resolve_env_backend();
        if kind == "s3" {
            Self::new_s3(
                config["bucket"].as_str().unwrap(),
                config.get("endpoint").and_then(|v| v.as_str()),
                config["region"].as_str().unwrap(),
                config["access_key"].as_str().unwrap(),
                config["secret_key"].as_str().unwrap(),
            )
        } else {
            Self::new_fs(config["path"].as_str().unwrap())
        }
    }

    /// Resolves the same env vars `from_env` does into a `(kind, config)` pair matching the
    /// `storage_backends` table's shape. Used by `from_env` itself and by `main.rs` at
    /// startup to persist the very first bootstrap backend as a DB row (so the DB becomes the
    /// source of truth going forward — see storage_backends.rs).
    pub fn resolve_env_backend() -> (String, serde_json::Value) {
        let backend = std::env::var("PLASTE_STORAGE_BACKEND").unwrap_or_else(|_| "fs".to_string());
        if backend == "s3" {
            let bucket = std::env::var("PLASTE_S3_BUCKET").expect("PLASTE_S3_BUCKET required for s3 backend");
            let region = std::env::var("PLASTE_S3_REGION").expect("PLASTE_S3_REGION required for s3 backend");
            let access_key =
                std::env::var("PLASTE_S3_ACCESS_KEY").expect("PLASTE_S3_ACCESS_KEY required for s3 backend");
            let secret_key =
                std::env::var("PLASTE_S3_SECRET_KEY").expect("PLASTE_S3_SECRET_KEY required for s3 backend");
            let endpoint = std::env::var("PLASTE_S3_ENDPOINT").ok();
            (
                "s3".to_string(),
                serde_json::json!({
                    "bucket": bucket, "region": region, "access_key": access_key,
                    "secret_key": secret_key, "endpoint": endpoint,
                }),
            )
        } else {
            let data_dir = std::env::var("PLASTE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
            let chunks_dir = Path::new(&data_dir).join("chunks");
            ("fs".to_string(), serde_json::json!({ "path": chunks_dir.to_string_lossy() }))
        }
    }

    fn path_for(&self, hash: &str) -> String {
        format!("{}/{hash}", &hash[0..2])
    }

    /// Clones the current hot-backend handle out from behind the lock. `Operator` is a cheap
    /// `Arc`-like handle (see opendal docs), so this is not a meaningful clone cost, and it
    /// lets every call site `.await` without holding the lock across an await point.
    fn op(&self) -> Operator {
        self.op.lock().unwrap().clone()
    }

    /// Builds an `Operator` from an admin-defined backend config (see `storage_backends.rs`).
    /// `kind` is `"fs"` or `"s3"`; `config` is the JSON blob stored in the `storage_backends`
    /// table (`{"path": "..."}` for fs — including CIFS/NFS, which from Plaste's perspective
    /// is just a local path the OS has already mounted a network share onto; `{"bucket":...,
    /// "region":..., ...}` for s3). Shared by `activate_backend` (runtime swap) and `main.rs`
    /// (startup bootstrap-from-DB).
    pub fn build_operator(kind: &str, config: &serde_json::Value) -> std::io::Result<Operator> {
        match kind {
            "fs" => {
                let path = config
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "fs config missing 'path'"))?;
                let builder = services::Fs::default().root(path);
                Operator::new(builder).map(|b| b.finish()).map_err(to_io_err)
            }
            "s3" => {
                let get = |k: &str| -> std::io::Result<String> {
                    config
                        .get(k)
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("s3 config missing '{k}'")))
                };
                let mut builder = services::S3::default()
                    .bucket(&get("bucket")?)
                    .region(&get("region")?)
                    .access_key_id(&get("access_key")?)
                    .secret_access_key(&get("secret_key")?);
                if let Some(endpoint) = config.get("endpoint").and_then(|v| v.as_str()) {
                    builder = builder.endpoint(endpoint);
                }
                Operator::new(builder).map(|b| b.finish()).map_err(to_io_err)
            }
            other => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("unknown backend kind {other:?}"))),
        }
    }

    /// Swaps the live hot backend to the one described by `kind`/`config`, taking effect
    /// immediately for all subsequent writes/reads. NOTE (deliberate MVP scope, same as
    /// hot/cold tiering's limitation): this does NOT migrate chunks already stored under the
    /// previously-active backend — only new writes land on the newly-activated backend. An
    /// admin switching backends is responsible for any migration of existing data.
    pub async fn activate_backend(&self, kind: &str, config: &serde_json::Value) -> std::io::Result<()> {
        let new_op = Self::build_operator(kind, config)?;
        *self.op.lock().unwrap() = new_op;
        Ok(())
    }

    /// Shared per-chunk body (dedup-check, encrypt, write blob, tiering bookkeeping) used by
    /// both `write` (CDC-splits a whole buffer) and `write_single_chunk` (already-hashed
    /// chunk from the client dedup-aware upload path, see chunk_upload.rs). Caller is
    /// responsible for `hash` actually matching `bytes` (verified at the HTTP boundary for
    /// the single-chunk path; always true for `write` since it computes the hash itself).
    async fn write_chunk_bytes(&self, hash: &str, bytes: &[u8]) -> std::io::Result<()> {
        let path = self.path_for(hash);
        // Dedup check is against the plaintext-hash key, same as before encryption was
        // added; only encrypt (with a fresh random nonce) if this content is new.
        if !self.op().exists(&path).await.map_err(to_io_err)? {
            let (key_id, ciphertext, nonce) = {
                let keyring = self.keyring.lock().unwrap();
                let (key_id, cipher) = keyring.current();
                let nonce = Nonce::generate();
                let ciphertext = cipher
                    .encrypt(&nonce, bytes)
                    .map_err(|e| std::io::Error::other(format!("chunk encryption failed: {e}")))?;
                (key_id.to_string(), ciphertext, nonce)
            };
            let mut stored = Vec::with_capacity(KEY_ID_LEN + NONCE_LEN + ciphertext.len());
            stored.extend_from_slice(&pad_id(&key_id));
            stored.extend_from_slice(&nonce);
            stored.extend_from_slice(&ciphertext);
            self.op().write(&path, stored).await.map_err(to_io_err)?;
        }
        if let Some(db) = &self.db {
            let now = chrono::Utc::now().to_rfc3339();
            let _ = db
                .execute(
                    "INSERT INTO chunk_access (hash, tier, last_accessed) VALUES ($1, 'hot', $2) \
                     ON CONFLICT(hash) DO UPDATE SET tier = 'hot', last_accessed = $2",
                    hiqlite::params!(hash.to_string(), now),
                )
                .await;
        }
        Ok(())
    }

    /// Splits data into content-defined chunks, writes new ones (dedup via BLAKE3 CAS),
    /// returns manifest (ordered list of chunk hashes) and total size.
    pub async fn write(&self, data: &[u8]) -> std::io::Result<(Vec<String>, i64)> {
        let mut manifest = Vec::new();
        for chunk in FastCDC::new(data, MIN, AVG, MAX) {
            let bytes = &data[chunk.offset..chunk.offset + chunk.length];
            let hash = blake3::hash(bytes).to_hex().to_string();
            self.write_chunk_bytes(&hash, bytes).await?;
            manifest.push(hash);
        }
        Ok((manifest, data.len() as i64))
    }

    /// Writes one already-hashed chunk (the chunk-aware upload path's `POST
    /// /chunks/upload/{hash}` — see chunk_upload.rs). Caller must have already verified
    /// `hash == blake3(bytes)` before calling this (this method trusts `hash` as given).
    pub async fn write_single_chunk(&self, hash: &str, bytes: &[u8]) -> std::io::Result<()> {
        self.write_chunk_bytes(hash, bytes).await
    }

    /// Reads the tier a chunk is currently stored in ('hot' if there's no tiering db attached
    /// or no row yet — i.e. the same behavior as before tiering existed).
    async fn tier_of(&self, hash: &str) -> String {
        let Some(db) = &self.db else { return "hot".to_string() };
        struct TierRow {
            tier: String,
        }
        impl From<&mut hiqlite::Row<'_>> for TierRow {
            fn from(row: &mut hiqlite::Row<'_>) -> Self {
                Self { tier: row.get("tier") }
            }
        }
        let row: Option<TierRow> = db
            .query_map_optional("SELECT tier FROM chunk_access WHERE hash = $1", hiqlite::params!(hash))
            .await
            .unwrap_or(None);
        row.map(|r| r.tier).unwrap_or_else(|| "hot".to_string())
    }

    pub async fn read_manifest(&self, manifest: &[String]) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        for hash in manifest {
            let tier = self.tier_of(hash).await;
            let path = self.path_for(hash);
            let buf = if tier == "cold" {
                let cold = self.cold.as_ref().expect("chunk_access says cold but no cold tier attached");
                let bytes = cold.read(&path).await.map_err(to_io_err)?.to_vec();
                // Promote back to hot on read: realistic tiering behavior — data that's
                // re-accessed after going cold is likely to be accessed again soon.
                self.op().write(&path, bytes.clone()).await.map_err(to_io_err)?;
                let _ = cold.delete(&path).await;
                if let Some(db) = &self.db {
                    let now = chrono::Utc::now().to_rfc3339();
                    let _ = db
                        .execute(
                            "UPDATE chunk_access SET tier = 'hot', last_accessed = $1 WHERE hash = $2",
                            hiqlite::params!(now, hash.clone()),
                        )
                        .await;
                }
                bytes
            } else {
                let bytes = self.op().read(&path).await.map_err(to_io_err)?.to_vec();
                if let Some(db) = &self.db {
                    let now = chrono::Utc::now().to_rfc3339();
                    let _ = db
                        .execute(
                            "UPDATE chunk_access SET last_accessed = $1 WHERE hash = $2",
                            hiqlite::params!(now, hash.clone()),
                        )
                        .await;
                }
                bytes
            };
            if buf.len() < KEY_ID_LEN + NONCE_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("chunk {hash} too short to contain a key id + nonce"),
                ));
            }
            let (key_id_bytes, rest) = buf.split_at(KEY_ID_LEN);
            let key_id_arr: [u8; KEY_ID_LEN] = key_id_bytes.try_into().unwrap();
            let key_id = unpad_id(&key_id_arr);
            let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
            let nonce = Nonce::try_from(nonce_bytes)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad nonce length"))?;
            let plaintext = {
                let keyring = self.keyring.lock().unwrap();
                let cipher = keyring.get(&key_id).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("chunk {hash} encrypted with unknown key id {key_id:?} (key rotated out / lost)"),
                    )
                })?;
                cipher
                    .decrypt(&nonce, ciphertext)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("chunk {hash} decryption failed: {e}")))?
            };
            out.extend_from_slice(&plaintext);
        }
        Ok(out)
    }

    /// Migrates chunks not read in `cold_after_days` days from hot to cold storage. Returns
    /// the number migrated. No-op (returns `Ok(0)`) if tiering isn't attached.
    pub async fn run_tiering_sweep(&self, cold_after_days: i64) -> std::io::Result<u64> {
        let (Some(db), Some(cold)) = (&self.db, &self.cold) else { return Ok(0) };

        struct HashRow {
            hash: String,
        }
        impl From<&mut hiqlite::Row<'_>> for HashRow {
            fn from(row: &mut hiqlite::Row<'_>) -> Self {
                Self { hash: row.get("hash") }
            }
        }

        let cutoff = (chrono::Utc::now() - chrono::Duration::days(cold_after_days)).to_rfc3339();
        let rows: Vec<HashRow> = db
            .query_map(
                "SELECT hash FROM chunk_access WHERE tier = 'hot' AND last_accessed < $1",
                hiqlite::params!(cutoff),
            )
            .await
            .map_err(std::io::Error::other)?;

        let mut migrated = 0u64;
        for row in rows {
            let path = self.path_for(&row.hash);
            let bytes = match self.op().read(&path).await {
                Ok(b) => b.to_vec(),
                Err(_) => continue, // blob already gone (e.g. gc'd); skip
            };
            cold.write(&path, bytes).await.map_err(to_io_err)?;
            self.op().delete(&path).await.map_err(to_io_err)?;
            db.execute(
                "UPDATE chunk_access SET tier = 'cold' WHERE hash = $1",
                hiqlite::params!(row.hash),
            )
            .await
            .map_err(std::io::Error::other)?;
            migrated += 1;
        }
        Ok(migrated)
    }

    /// Local-disk path for a chunk blob, only meaningful for the fs backend (returns `None`
    /// for S3-backed stores). Prefer `chunk_exists` for backend-agnostic checks.
    pub fn chunk_path(&self, hash: &str) -> Option<PathBuf> {
        self.root.as_ref().map(|root| root.join(&hash[0..2]).join(hash))
    }

    pub async fn chunk_exists(&self, hash: &str) -> std::io::Result<bool> {
        self.op().exists(&self.path_for(hash)).await.map_err(to_io_err)
    }

    /// Removes a chunk blob from storage. Missing blob is not an error (already gone).
    pub async fn delete_chunk(&self, hash: &str) -> std::io::Result<()> {
        self.op().delete(&self.path_for(hash)).await.map_err(to_io_err)
    }

    /// Rotates the master keyring: generates a new key, makes it current for all future
    /// writes, and keeps the old key(s) around so existing chunks still decrypt. Returns the
    /// new key id.
    pub async fn rotate_key(&self) -> std::io::Result<String> {
        let mut keyring = self.keyring.lock().unwrap();
        keyring.rotate(&master_key_dir())
    }
}

fn to_io_err(e: opendal::Error) -> std::io::Error {
    std::io::Error::other(e)
}

pub async fn ensure_dir(p: &Path) {
    let _ = fs::create_dir_all(p).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fs_backend_write_read_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::new_fs(dir.path());

        let data = b"hello world, this is some test chunk data for opendal".to_vec();
        let (manifest, size) = store.write(&data).await.unwrap();
        assert_eq!(size as usize, data.len());

        let read_back = store.read_manifest(&manifest).await.unwrap();
        assert_eq!(read_back, data);

        // second write of identical content should hit the dedup ("already exists") path
        // without erroring.
        let (manifest2, _) = store.write(&data).await.unwrap();
        assert_eq!(manifest, manifest2);
    }

    #[tokio::test]
    async fn chunks_are_encrypted_at_rest_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChunkStore::new_fs(dir.path());

        let data = b"plaintext that must not appear verbatim on disk".to_vec();
        let (manifest, _) = store.write(&data).await.unwrap();

        // Bypass ChunkStore and read the raw file the fs backend wrote.
        let hash = &manifest[0];
        let raw_path = dir.path().join(&hash[0..2]).join(hash);
        let raw = tokio::fs::read(&raw_path).await.unwrap();

        assert_ne!(raw, data, "stored bytes must not match plaintext");
        assert!(
            raw.len() >= data.len() + crate::crypto::KEY_ID_LEN + 12,
            "expect key_id + nonce + ciphertext (+ GCM tag) overhead"
        );

        // Round-trip through ChunkStore still yields the original plaintext.
        let read_back = store.read_manifest(&manifest).await.unwrap();
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn tiering_sweep_migrates_cold_and_read_transparently_promotes_back_to_hot() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::init(dir.path().to_str().unwrap()).await;
        crate::tiering::init_schema(&db).await;

        let hot_dir = dir.path().join("chunks_hot");
        let cold_dir = dir.path().join("chunks_cold");
        tokio::fs::create_dir_all(&hot_dir).await.unwrap();
        tokio::fs::create_dir_all(&cold_dir).await.unwrap();

        let store = ChunkStore::new_fs(&hot_dir).with_tiering(ChunkStore::new_fs_cold(&cold_dir), db.clone());

        let data = b"tiered chunk data that should migrate hot to cold and back".to_vec();
        let (manifest, _size) = store.write(&data).await.unwrap();
        let hash = manifest[0].clone();

        // Backdate last_accessed so the sweep picks it up with a 1-day threshold.
        let old = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();
        db.execute(
            "UPDATE chunk_access SET last_accessed = $1 WHERE hash = $2",
            hiqlite::params!(old, hash.clone()),
        )
        .await
        .unwrap();

        let migrated = store.run_tiering_sweep(1).await.unwrap();
        assert_eq!(migrated, 1);

        let hot_path = hot_dir.join(&hash[0..2]).join(&hash);
        let cold_path = cold_dir.join(&hash[0..2]).join(&hash);
        assert!(!hot_path.exists(), "blob should be gone from hot after migration");
        assert!(cold_path.exists(), "blob should now be in cold");

        // Transparent read: still returns correct plaintext via the cold path.
        let read_back = store.read_manifest(&manifest).await.unwrap();
        assert_eq!(read_back, data);

        // Promote-back-to-hot: after the read, blob is back in hot and tier is 'hot' again.
        assert!(hot_path.exists(), "blob should be promoted back to hot after read");
        assert!(!cold_path.exists(), "blob should be removed from cold after promotion");

        struct TierRow {
            tier: String,
        }
        impl From<&mut hiqlite::Row<'_>> for TierRow {
            fn from(row: &mut hiqlite::Row<'_>) -> Self {
                Self { tier: row.get("tier") }
            }
        }
        let row: Option<TierRow> = db
            .query_map_optional("SELECT tier FROM chunk_access WHERE hash = $1", hiqlite::params!(hash))
            .await
            .unwrap();
        assert_eq!(row.unwrap().tier, "hot");
    }

    #[test]
    fn s3_backend_constructs_without_panicking() {
        // Building the Operator is local/lazy; no network call happens until an actual
        // read/write, so this doesn't require real credentials or a live bucket.
        let _store = ChunkStore::new_s3(
            "test-bucket",
            Some("http://localhost:9000"),
            "us-east-1",
            "fake-access-key",
            "fake-secret-key",
        );
    }

    #[tokio::test]
    async fn activate_backend_swaps_hot_operator_for_new_writes() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let store = ChunkStore::new_fs(dir_a.path());

        let (manifest_a, _) = store.write(b"data written before activation").await.unwrap();
        let hash_a = manifest_a[0].clone();
        assert!(dir_a.path().join(&hash_a[0..2]).join(&hash_a).exists());

        let config = serde_json::json!({ "path": dir_b.path().to_string_lossy() });
        store.activate_backend("fs", &config).await.unwrap();

        let (manifest_b, _) = store.write(b"data written after activation, different bytes").await.unwrap();
        let hash_b = manifest_b[0].clone();
        assert!(dir_b.path().join(&hash_b[0..2]).join(&hash_b).exists(), "post-activation write should land in new backend");
        assert!(!dir_a.path().join(&hash_b[0..2]).join(&hash_b).exists(), "post-activation write should NOT land in old backend");
    }
}
