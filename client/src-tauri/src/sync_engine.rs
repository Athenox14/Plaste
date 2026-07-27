// Sync engine: intentionally minimal. A full run_sync_pass(client, watcher_events)
// needs a local-file <-> remote-file mapping persistence layer that doesn't exist
// yet, so it's not attempted here (not faked either). What IS wired end-to-end is
// a real connectivity/auth check against the live backend, plus real delta-sync
// of a single already-known (file_id, base_version) pair.
//
// ponytail: no local<->remote path mapping store, so this doesn't decide *which*
// file/base_version to sync (that needs the mapping layer) — it only performs a
// real delta transfer given the caller already knows both.

use crate::api_client::{PlasteClient, UploadResp};

// Same CDC constants as the backend's src/storage.rs — consistency only matters within one
// side's own chunking (chunks are content-addressed, so client/server naturally agree
// regardless of any version skew in the fastcdc crate itself).
const CDC_MIN: usize = 256 * 1024;
const CDC_AVG: usize = 1024 * 1024;
const CDC_MAX: usize = 4 * 1024 * 1024;

/// Chunk-aware upload: splits `data` into content-defined chunks locally, asks the server
/// which ones it's missing, and transmits only those — the real bandwidth-saving dedup path
/// (as opposed to `upload_file`, which always sends the whole file). Returns a human-readable
/// summary of how much was actually sent vs. the total.
pub async fn upload_file_dedup_aware(
    client: &PlasteClient,
    folder_id: Option<i64>,
    name: &str,
    data: &[u8],
) -> Result<String, String> {
    let chunker = fastcdc::v2020::FastCDC::new(data, CDC_MIN, CDC_AVG, CDC_MAX);
    let mut manifest = Vec::new();
    let mut chunk_bytes: Vec<(String, Vec<u8>)> = Vec::new();
    for chunk in chunker {
        let bytes = &data[chunk.offset..chunk.offset + chunk.length];
        let hash = blake3::hash(bytes).to_hex().to_string();
        manifest.push(hash.clone());
        chunk_bytes.push((hash, bytes.to_vec()));
    }

    let hashes: Vec<String> = manifest.clone();
    let missing = client.check_missing_chunks(&hashes).await?;
    let missing_set: std::collections::HashSet<&String> = missing.iter().collect();

    let mut sent_bytes: u64 = 0;
    // ponytail: sequential upload, not parallel-batched — a few-chunk-at-a-time join_all
    // would be the next step if throughput on many-chunk files becomes a bottleneck.
    for (hash, bytes) in &chunk_bytes {
        if missing_set.contains(hash) {
            sent_bytes += bytes.len() as u64;
            client.upload_chunk(hash, bytes.clone()).await?;
        }
    }

    let total_bytes: u64 = data.len() as u64;
    client
        .finalize_file(folder_id, name, manifest.clone(), data.len() as i64, None)
        .await?;

    Ok(format!(
        "uploaded {}/{} chunks ({} bytes sent of {} total)",
        missing.len(),
        chunk_bytes.len(),
        sent_bytes,
        total_bytes
    ))
}

#[tauri::command]
pub async fn upload_file_dedup_aware_cmd(
    base_url: String,
    token: String,
    folder_id: Option<i64>,
    name: String,
    data: Vec<u8>,
) -> Result<String, String> {
    let client = PlasteClient::new(base_url, token);
    upload_file_dedup_aware(&client, folder_id, &name, &data).await
}

#[tauri::command]
pub async fn test_connection(base_url: String, token: String) -> Result<String, String> {
    let client = PlasteClient::new(base_url, token);
    let contents = client.list_folder(None).await?;
    Ok(format!(
        "connected: {} folder(s), {} file(s) at root",
        contents.folders.len(),
        contents.files.len()
    ))
}

/// Real delta-sync: fetches the remote signature for `base_version`, diffs
/// `local_new_content` against it locally, and uploads only the delta — the whole file
/// never crosses the wire.
pub async fn sync_file_delta(
    client: &PlasteClient,
    file_id: i64,
    base_version: i64,
    local_new_content: &[u8],
) -> Result<UploadResp, String> {
    let sig_bytes = client.get_signature(file_id, base_version).await?;
    let signature = fast_rsync::Signature::deserialize(sig_bytes).map_err(|e| e.to_string())?;

    let mut delta = Vec::new();
    fast_rsync::diff(&signature.index(), local_new_content, &mut delta).map_err(|e| e.to_string())?;

    client.upload_delta(file_id, base_version, delta).await
}

#[tauri::command]
pub async fn sync_file_delta_cmd(
    base_url: String,
    token: String,
    file_id: i64,
    base_version: i64,
    local_new_content: Vec<u8>,
) -> Result<UploadResp, String> {
    let client = PlasteClient::new(base_url, token);
    sync_file_delta(&client, file_id, base_version, &local_new_content).await
}
