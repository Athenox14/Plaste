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
