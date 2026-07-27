// Real end-to-end smoke test against a live backend server, per task instructions.
// Run manually with the backend up: cargo test --test smoketest_live -- --ignored --nocapture
// (ignored by default so normal `cargo test`/`cargo build` never needs a live server).

#[path = "../src/api_client.rs"]
mod api_client;

use api_client::PlasteClient;

#[tokio::test]
#[ignore]
async fn list_root_against_live_backend() {
    let base_url = std::env::var("PLASTE_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:8097".into());
    let token = std::env::var("PLASTE_TEST_TOKEN").expect("set PLASTE_TEST_TOKEN");
    let client = PlasteClient::new(base_url, token);
    let contents = client.list_folder(None).await.expect("list_folder(None) should succeed");
    assert!(contents.folders.is_empty());
    assert!(contents.files.is_empty());
}
