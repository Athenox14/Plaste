// Minimal HTTP client for the Plaste backend (GET /folders[/{id}], POST /files/upload,
// GET /files/{id}/download). Retries transient failures with backon, and caches
// downloaded file bytes with moka to avoid redundant re-downloads during a sync pass.

use backon::{ExponentialBuilder, Retryable};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubFolder {
    pub id: i64,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileEntry {
    pub id: i64,
    pub name: String,
    pub size: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FolderContents {
    pub folders: Vec<SubFolder>,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UploadResp {
    pub file_id: i64,
    pub version_id: i64,
    pub version_no: i64,
    pub size: i64,
}

pub struct PlasteClient {
    pub base_url: String,
    pub token: String,
    http: reqwest::Client,
    // Cache of downloaded file bytes by file_id: 50 entries / 5 min TTL, meant to
    // avoid re-downloading the same file repeatedly during a sync pass.
    dl_cache: Cache<i64, Vec<u8>>,
}

fn retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default().with_max_times(3)
}

impl PlasteClient {
    pub fn new(base_url: String, token: String) -> Self {
        Self {
            base_url,
            token,
            http: reqwest::Client::new(),
            dl_cache: Cache::builder()
                .max_capacity(50)
                .time_to_live(Duration::from_secs(5 * 60))
                .build(),
        }
    }

    /// Lists a folder's contents; `None` lists the root.
    pub async fn list_folder(&self, folder_id: Option<i64>) -> Result<FolderContents, String> {
        let url = match folder_id {
            Some(id) => format!("{}/folders/{id}", self.base_url),
            None => format!("{}/folders", self.base_url),
        };
        (|| async {
            self.http
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?
                .error_for_status()?
                .json::<FolderContents>()
                .await
        })
        .retry(retry_policy())
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn upload_file(
        &self,
        folder_id: Option<i64>,
        name: &str,
        bytes: Vec<u8>,
    ) -> Result<UploadResp, String> {
        let url = format!("{}/files/upload", self.base_url);
        (|| async {
            let mut form = reqwest::multipart::Form::new()
                .text("name", name.to_string())
                .part(
                    "file",
                    reqwest::multipart::Part::bytes(bytes.clone())
                        .file_name(name.to_string()),
                );
            if let Some(id) = folder_id {
                form = form.text("folder_id", id.to_string());
            }
            self.http
                .post(&url)
                .bearer_auth(&self.token)
                .multipart(form)
                .send()
                .await?
                .error_for_status()?
                .json::<UploadResp>()
                .await
        })
        .retry(retry_policy())
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn download_file(&self, file_id: i64) -> Result<Vec<u8>, String> {
        if let Some(cached) = self.dl_cache.get(&file_id).await {
            return Ok(cached);
        }
        let url = format!("{}/files/{file_id}/download", self.base_url);
        let bytes = (|| async {
            self.http
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await
        })
        .retry(retry_policy())
        .await
        .map_err(|e| e.to_string())?
        .to_vec();
        self.dl_cache.insert(file_id, bytes.clone()).await;
        Ok(bytes)
    }

    /// Fetches a serialized `fast_rsync::Signature` for `version` of `file_id`, so the
    /// caller can compute a delta against it locally without downloading the whole file.
    pub async fn get_signature(&self, file_id: i64, version: i64) -> Result<Vec<u8>, String> {
        let url = format!("{}/files/{file_id}/signature?version={version}", self.base_url);
        (|| async {
            self.http
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await
        })
        .retry(retry_policy())
        .await
        .map_err(|e| e.to_string())
        .map(|b| b.to_vec())
    }

    /// Uploads a `fast_rsync` delta computed against `base_version`; the server
    /// reconstructs the full new version from it. Only the delta bytes travel over the
    /// network, not the whole file.
    pub async fn upload_delta(
        &self,
        file_id: i64,
        base_version: i64,
        delta: Vec<u8>,
    ) -> Result<UploadResp, String> {
        let url = format!(
            "{}/files/{file_id}/upload-delta?base_version={base_version}",
            self.base_url
        );
        (|| async {
            self.http
                .post(&url)
                .bearer_auth(&self.token)
                .body(delta.clone())
                .send()
                .await?
                .error_for_status()?
                .json::<UploadResp>()
                .await
        })
        .retry(retry_policy())
        .await
        .map_err(|e| e.to_string())
    }
}

// ponytail: no unit test harness dep (mockito etc) added just for this — the real
// end-to-end proof is the #[tokio::test] run manually against a live backend
// during verification, not a permanent fixture here.
