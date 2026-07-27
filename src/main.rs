use std::sync::Arc;

use plaste::{admin, audit, auth, comments, db, files, folders, gc, graphql, groups, keymgmt, mcp, ratelimit,
    retention, search, sharing, state::AppState, storage, tags, tiering, trash, tus};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let data_dir = std::env::var("PLASTE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let chunks_dir = std::path::Path::new(&data_dir).join("chunks");
    storage::ensure_dir(std::path::Path::new(&data_dir)).await;
    storage::ensure_dir(&chunks_dir).await;

    let db = db::init(&data_dir).await;
    audit::init_schema(&db).await;
    comments::init_schema(&db).await;
    tags::init_schema(&db).await;
    retention::init_schema(&db).await;
    files::init_schema(&db).await;
    tiering::init_schema(&db).await;
    tus::init_schema(&db).await;

    let fts_dir = std::path::Path::new(&data_dir).join("fts_index");
    let fts = plaste::fulltext::FullTextIndex::open_or_create(&fts_dir).expect("open fts index");

    let cold_root = std::path::Path::new(&data_dir).join("chunks_cold");
    storage::ensure_dir(&cold_root).await;
    let cold_op = storage::ChunkStore::new_fs_cold(&cold_root);
    let chunk_store = storage::ChunkStore::from_env().with_tiering(cold_op, db.clone());

    let state = AppState {
        db,
        storage: Arc::new(chunk_store),
        chunks_dir,
        fts: Arc::new(fts),
    };

    auth::bootstrap_admin(&state).await;

    // ponytail: fixed 1h cadence, not configurable; add a config knob if ops ever need finer control.
    let retention_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            if let Err((_, msg)) = retention::purge_expired_trash(&retention_state).await {
                tracing::warn!("retention sweep failed: {msg}");
            }
        }
    });

    let tiering_storage = state.storage.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match tiering_storage.run_tiering_sweep(30).await {
                Ok(n) if n > 0 => tracing::info!("tiering sweep migrated {n} chunks to cold"),
                Ok(_) => {}
                Err(e) => tracing::warn!("tiering sweep failed: {e}"),
            }
        }
    });

    // Rate limits (tunable): general safety net for the TokenCtx DB-lookup path on every
    // route, plus a stricter quota stacked on top of the upload-heavy routers (files::router()
    // also covers download/preview/versions alongside upload; tus::router() is upload-only).
    // ponytail: applied to the whole sub-router rather than a single path, since isolating just
    // POST /files/upload would mean editing files.rs (owned by another agent right now).
    let general_limit = ratelimit::general(); // ~100 req/min per IP
    let upload_limit = ratelimit::upload(); // ~20 req/min per IP

    // Defensive backstop, not a primary cleanup path: refcount decrements already happen
    // synchronously on purge (trash.rs/retention.rs), so this only catches stragglers.
    let gc_db = state.db.clone();
    let gc_storage = state.storage.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(6 * 60 * 60)).await;
            match gc::sweep_orphaned_chunks(&gc_db, &gc_storage).await {
                Ok(n) if n > 0 => tracing::info!("chunk gc swept {n} orphaned chunks"),
                Ok(_) => {}
                Err(e) => tracing::warn!("chunk gc sweep failed: {e}"),
            }
        }
    });

    let app = axum::Router::new()
        .merge(admin::router())
        .merge(audit::router())
        .merge(comments::router())
        .merge(files::router().layer(upload_limit.clone()))
        .merge(folders::router())
        .merge(graphql::router())
        .merge(groups::router())
        .merge(keymgmt::router())
        .merge(mcp::router())
        .merge(retention::router())
        .merge(search::router())
        .merge(sharing::router())
        .merge(tags::router())
        .merge(trash::router())
        .merge(tus::router().layer(upload_limit))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(general_limit)
        // ponytail: permissive CORS — this is a self-hosted server behind bearer-token auth,
        // not cookie-based sessions, so a wide-open Access-Control-Allow-Origin carries no
        // CSRF-style risk here; tighten to an allowlist if that assumption ever changes.
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        );

    let port = std::env::var("PLASTE_PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("127.0.0.1:{port}");

    let tls_paths = std::env::var("PLASTE_TLS_CERT").ok().zip(std::env::var("PLASTE_TLS_KEY").ok());
    match tls_paths {
        Some((cert, key)) => {
            tracing::info!("listening on {addr} (TLS enabled)");
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .expect("load TLS cert/key");
            let socket_addr: std::net::SocketAddr = addr.parse().expect("valid addr");
            axum_server::bind_rustls(socket_addr, config)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .expect("server");
        }
        None => {
            tracing::info!("listening on {addr} (plain HTTP)");
            let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .expect("server");
        }
    }
}
