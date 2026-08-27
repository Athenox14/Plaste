use aes_gcm::aead::{Generate, Key};
use aes_gcm::Aes256Gcm;
use std::collections::HashMap;
use std::io;
use std::path::Path;

/// Fixed width every key id is padded/truncated to on the chunk wire format (see
/// `storage.rs`) — keeps the key-id prefix unambiguous without needing a length byte.
pub const KEY_ID_LEN: usize = 8;

pub fn pad_id(id: &str) -> [u8; KEY_ID_LEN] {
    let mut out = [b'_'; KEY_ID_LEN];
    let bytes = id.as_bytes();
    let n = bytes.len().min(KEY_ID_LEN);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

pub fn unpad_id(raw: &[u8; KEY_ID_LEN]) -> String {
    String::from_utf8_lossy(raw).trim_end_matches('_').to_string()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    current_key_id: String,
    keys: HashMap<String, String>, // base64-encoded 32-byte keys
}

/// Master keyring for chunk-blob encryption at rest, supporting rotation: multiple keys kept
/// around (to decrypt old chunks), one marked "current" (used for all new writes).
///
/// ponytail: keys live in a plaintext JSON file on local disk, no KMS/HSM. Upgrade path:
/// per-tenant keys + envelope encryption via a real KMS if that's ever needed.
pub struct KeyRing {
    // Raw key bytes are retained (not just the derived `Aes256Gcm` ciphers) so `rotate` can
    // re-persist the full key file without needing to recover key material from a cipher.
    raw_keys: HashMap<String, [u8; 32]>,
    ciphers: HashMap<String, Aes256Gcm>,
    current_key_id: String,
}

impl KeyRing {
    fn key_file_path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join("master_keys.json")
    }

    /// Loads the keyring from `<data_dir>/master_keys.json`, migrating from the old single-key
    /// `<data_dir>/master.key` format (32 raw bytes) if that's all that exists, or generating a
    /// fresh key (`k1`) if neither exists.
    pub fn load_or_init(data_dir: &Path) -> io::Result<Self> {
        let key_file_path = Self::key_file_path(data_dir);

        if key_file_path.exists() {
            let raw = std::fs::read_to_string(&key_file_path)?;
            let file: KeyFile = serde_json::from_str(&raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Self::from_key_file(file);
        }

        std::fs::create_dir_all(data_dir)?;

        // Migrate old-format master.key (32 raw bytes) if present; else generate a fresh key.
        let old_key_path = data_dir.join("master.key");
        let key: [u8; 32] = if old_key_path.exists() {
            let raw = std::fs::read(&old_key_path)?;
            raw.try_into().map_err(|v: Vec<u8>| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} must contain 32 bytes, got {}", old_key_path.display(), v.len()),
                )
            })?
        } else {
            Key::<Aes256Gcm>::generate().into()
        };

        let mut keys = HashMap::new();
        keys.insert("k1".to_string(), base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key));
        let file = KeyFile { current_key_id: "k1".to_string(), keys };
        Self::persist(data_dir, &file)?;
        Self::from_key_file(file)
    }

    fn from_key_file(file: KeyFile) -> io::Result<Self> {
        use aes_gcm::KeyInit;
        let mut raw_keys = HashMap::new();
        let mut ciphers = HashMap::new();
        for (id, b64) in &file.keys {
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                io::Error::new(io::ErrorKind::InvalidData, format!("key {id} must be 32 bytes, got {}", v.len()))
            })?;
            ciphers.insert(id.clone(), Aes256Gcm::new(&Key::<Aes256Gcm>::from(key)));
            raw_keys.insert(id.clone(), key);
        }
        if !ciphers.contains_key(&file.current_key_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("current_key_id {} not found in keys", file.current_key_id),
            ));
        }
        Ok(Self { raw_keys, ciphers, current_key_id: file.current_key_id })
    }

    fn to_key_file(&self) -> KeyFile {
        let keys = self
            .raw_keys
            .iter()
            .map(|(id, key)| (id.clone(), base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key)))
            .collect();
        KeyFile { current_key_id: self.current_key_id.clone(), keys }
    }

    fn persist(data_dir: &Path, file: &KeyFile) -> io::Result<()> {
        let json = serde_json::to_string_pretty(file).map_err(io::Error::other)?;
        std::fs::write(Self::key_file_path(data_dir), json)
    }

    /// The key id and cipher used for new writes.
    pub fn current(&self) -> (&str, &Aes256Gcm) {
        let cipher = self.ciphers.get(&self.current_key_id).expect("current key always present");
        (&self.current_key_id, cipher)
    }

    /// Derives a purpose-bound 32-byte subkey from the *current* master key.
    ///
    /// Security: BLAKE3's `derive_key` is a KDF with domain separation by `context`, so a subkey
    /// handed to some other subsystem (e.g. signing short-lived share download tickets) can
    /// never be used to decrypt chunks, and two contexts can't produce the same subkey. The
    /// master key never leaves this type.
    ///
    /// Note this follows the current key: after `rotate`, subkeys change too. Anything derived
    /// here must therefore be short-lived or re-derivable, never long-term stored state.
    pub fn derive_subkey(&self, context: &str) -> [u8; 32] {
        let master = self.raw_keys.get(&self.current_key_id).expect("current key always present");
        blake3::derive_key(context, master)
    }

    /// Looks up a cipher by key id (as read back from a chunk's wire prefix, already unpadded).
    pub fn get(&self, key_id: &str) -> Option<&Aes256Gcm> {
        self.ciphers.get(key_id)
    }

    /// Generates a brand new key, adds it to the ring, makes it current, persists the updated
    /// `master_keys.json`, and returns the new key id.
    pub fn rotate(&mut self, data_dir: &Path) -> io::Result<String> {
        use aes_gcm::KeyInit;
        // ponytail: simple incrementing id derived from ring size; fine for a handful of
        // rotations over the life of a deployment.
        let mut n = self.raw_keys.len() + 1;
        let mut new_id = format!("k{n}");
        while self.raw_keys.contains_key(&new_id) {
            n += 1;
            new_id = format!("k{n}");
        }

        let key: [u8; 32] = Key::<Aes256Gcm>::generate().into();
        self.raw_keys.insert(new_id.clone(), key);
        self.ciphers.insert(new_id.clone(), Aes256Gcm::new(&Key::<Aes256Gcm>::from(key)));
        self.current_key_id = new_id.clone();

        Self::persist(data_dir, &self.to_key_file())?;
        Ok(new_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;

    #[test]
    fn fresh_keyring_generates_k1_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let ring = KeyRing::load_or_init(dir.path()).unwrap();
        let (id, cipher) = ring.current();
        assert_eq!(id, "k1");

        let nonce = aes_gcm::Nonce::generate();
        let ct = cipher.encrypt(&nonce, b"hello".as_slice()).unwrap();
        let pt = ring.get("k1").unwrap().decrypt(&nonce, ct.as_slice()).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn rotate_makes_new_key_current_and_keeps_old_key_decryptable() {
        let dir = tempfile::tempdir().unwrap();
        let mut ring = KeyRing::load_or_init(dir.path()).unwrap();

        // Encrypt something under the original current key (k1).
        let (old_id, old_cipher) = {
            let (id, cipher) = ring.current();
            (id.to_string(), cipher.clone())
        };
        let nonce = aes_gcm::Nonce::generate();
        let ct = old_cipher.encrypt(&nonce, b"old data".as_slice()).unwrap();

        let new_id = ring.rotate(dir.path()).unwrap();
        assert_ne!(new_id, old_id);
        assert_eq!(ring.current().0, new_id);

        // Old chunk still decrypts via the retained old key.
        let pt = ring.get(&old_id).unwrap().decrypt(&nonce, ct.as_slice()).unwrap();
        assert_eq!(pt, b"old data");

        // Reload from disk: rotation was persisted.
        let reloaded = KeyRing::load_or_init(dir.path()).unwrap();
        assert_eq!(reloaded.current().0, new_id);
        assert!(reloaded.get(&old_id).is_some());
    }

    #[test]
    fn migrates_old_format_master_key_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let old_key: [u8; 32] = Key::<Aes256Gcm>::generate().into();
        std::fs::write(dir.path().join("master.key"), old_key).unwrap();

        let ring = KeyRing::load_or_init(dir.path()).unwrap();
        let (id, cipher) = ring.current();
        assert_eq!(id, "k1");

        // New master_keys.json now exists and chunks encrypted under it decrypt fine.
        assert!(dir.path().join("master_keys.json").exists());
        let nonce = aes_gcm::Nonce::generate();
        let ct = cipher.encrypt(&nonce, b"migrated".as_slice()).unwrap();
        let pt = ring.get("k1").unwrap().decrypt(&nonce, ct.as_slice()).unwrap();
        assert_eq!(pt, b"migrated");
    }
}
