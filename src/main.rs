use std::io::Write;
use std::sync::Arc;

use plaste::{admin, audit, auth, chunk_upload, comments, db, files, folders, gc, graphql, groups, keymgmt, mcp,
    ratelimit, retention, search, share_page, sharing, state::AppState, storage, storage_backends, tags, tiering, trash, tus};

// TEMPORARY: startup breadcrumbs for diagnosing a silent-exit-0 bug that only reproduces
// inside the container. Bypasses the tracing subscriber entirely (raw eprintln! + explicit
// flush) so a step is visible even if RUST_LOG/tracing init itself is the thing failing.
// Remove once the silent-exit root cause is confirmed and fixed.
macro_rules! breadcrumb {
    ($($arg:tt)*) => {{
        eprintln!("[startup] {}", format!($($arg)*));
        let _ = std::io::stderr().flush();
    }};
}

#[tokio::main]
async fn main() {
    breadcrumb!("main() entered");

    tracing_subscriber::fmt::init();
    breadcrumb!("tracing_subscriber initialized");

    let data_dir = std::env::var("PLASTE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let chunks_dir = std::path::Path::new(&data_dir).join("chunks");
    breadcrumb!("data_dir resolved: {data_dir}");
    storage::ensure_dir(std::path::Path::new(&data_dir)).await;
    storage::ensure_dir(&chunks_dir).await;
    breadcrumb!("data/chunks dirs ensured");

    let db = db::init(&data_dir).await;
    breadcrumb!("db::init (hiqlite) returned");
    audit::init_schema(&db).await;
    comments::init_schema(&db).await;
    tags::init_schema(&db).await;
    retention::init_schema(&db).await;
    files::init_schema(&db).await;
    tiering::init_schema(&db).await;
    tus::init_schema(&db).await;
    storage_backends::init_schema(&db).await;
    breadcrumb!("all init_schema calls returned");

    let fts_dir = std::path::Path::new(&data_dir).join("fts_index");
    let fts = plaste::fulltext::FullTextIndex::open_or_create(&fts_dir).expect("open fts index");
    breadcrumb!("fulltext index opened");

    let cold_root = std::path::Path::new(&data_dir).join("chunks_cold");
    storage::ensure_dir(&cold_root).await;
    let cold_op = storage::ChunkStore::new_fs_cold(&cold_root);
    let chunk_store = storage::ChunkStore::from_env().with_tiering(cold_op, db.clone());
    breadcrumb!("chunk store constructed");

    // Admin-configurable storage backends (storage_backends.rs): if the DB already has an
    // active backend row, that's the source of truth — swap the just-built (from_env) hot
    // backend to point at it. Otherwise this is the very first run: persist whatever
    // from_env() resolved to as the first row (marked active), so the DB becomes the source
    // of truth from here on and admins can list/switch via the API.
    struct ActiveBackendRow {
        kind: String,
        config: String,
    }
    impl From<&mut hiqlite::Row<'_>> for ActiveBackendRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self { kind: row.get("kind"), config: row.get("config") }
        }
    }
    let active: Option<ActiveBackendRow> = db
        .query_map_optional("SELECT kind, config FROM storage_backends WHERE is_active = 1", hiqlite::params!())
        .await
        .unwrap_or(None);
    match active {
        Some(row) => {
            let config: serde_json::Value = serde_json::from_str(&row.config).expect("stored storage_backends config is valid JSON");
            chunk_store
                .activate_backend(&row.kind, &config)
                .await
                .expect("activate DB-configured storage backend at startup");
        }
        None => {
            let (kind, config) = storage::ChunkStore::resolve_env_backend();
            let config_str = serde_json::to_string(&config).expect("serialize bootstrap backend config");
            db.execute(
                "INSERT INTO storage_backends (name, kind, config, is_active, created_at) VALUES ('bootstrap', $1, $2, 1, $3)",
                hiqlite::params!(&kind, &config_str, chrono::Utc::now().to_rfc3339()),
            )
            .await
            .expect("persist bootstrap storage backend row");
        }
    }
    breadcrumb!("storage backend activation resolved");

    let state = AppState {
        db,
        storage: Arc::new(chunk_store),
        chunks_dir,
        fts: Arc::new(fts),
    };

    auth::bootstrap_admin(&state).await;
    breadcrumb!("auth::bootstrap_admin returned");

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
        .merge(chunk_upload::router().layer(upload_limit.clone()))
        .merge(comments::router())
        // Borne de corps EXPLICITE sur les envois en une seule requete.
        //
        // Sans elle, la valeur par defaut d'axum s'appliquait : 2 Mio. Tout
        // fichier au-dela repondait 413, y compris quand le proxy en amont
        // acceptait 10 Gio — le plafond reel etait ici, et invisible.
        //
        // Pourquoi 256 Mio et pas 10 Gio : `upload` lit le champ avec
        // `field.bytes()`, donc le fichier tient ENTIEREMENT en memoire, et le
        // conteneur est limite a 1 Gio. Autoriser 10 Gio ne ferait pas passer
        // les gros fichiers, ca tuerait le processus au premier essai et
        // couperait le stockage de tout le monde.
        //
        // Au-dela de cette borne, la voie est l'envoi par morceaux (tus /
        // chunks, 8 Mio par requete), qui ne charge jamais le fichier entier.
        .merge(files::router()
            .layer(upload_limit.clone())
            .layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024)))
        .merge(folders::router())
        .merge(graphql::router())
        .merge(groups::router())
        .merge(keymgmt::router())
        .merge(mcp::router())
        .merge(retention::router())
        .merge(search::router())
        .merge(share_page::router())
        .merge(sharing::router())
        .merge(storage_backends::router())
        .merge(tags::router())
        .merge(trash::router())
        // Meme raison que pour files: la valeur par defaut d'axum (2 Mio)
        // s'appliquait aux PATCH tus, ce qui bornait chaque tranche a 2 Mio sans
        // que rien ne le dise. 8 Mio est sans risque ici : une tranche est
        // ajoutee au fichier partiel sur disque, jamais accumulee.
        .merge(tus::router()
            .layer(upload_limit)
            .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024)))
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
    breadcrumb!("router built");

    let port = std::env::var("PLASTE_PORT").unwrap_or_else(|_| "8080".to_string());
    // [::] plutôt que 0.0.0.0 : le réseau pod du cluster cible est IPv6-only
    // (Cilium fd42::/...), le Service ne route que vers l'IP par défaut du pod
    // (eth0, IPv6) — un bind IPv4-only n'a aucune interface à écouter dessus
    // sur ce type de cluster et rend le pod injoignable malgré un "listening"
    // en logs. Un socket IPv6 dual-stack Linux accepte aussi les connexions
    // IPv4-mappées, donc ça reste compatible avec un déploiement IPv4 classique.
    let addr = format!("[::]:{port}");

    let tls_paths = std::env::var("PLASTE_TLS_CERT").ok().zip(std::env::var("PLASTE_TLS_KEY").ok());
    breadcrumb!("tls_paths resolved: {}", tls_paths.is_some());
    match tls_paths {
        Some((cert, key)) => {
            tracing::info!("listening on {addr} (TLS enabled)");
            breadcrumb!("loading TLS cert/key from {cert} / {key}");
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .expect("load TLS cert/key");
            breadcrumb!("TLS config loaded");
            let socket_addr: std::net::SocketAddr = addr.parse().expect("valid addr");
            breadcrumb!("about to bind_rustls on {socket_addr}");
            axum_server::bind_rustls(socket_addr, config)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .expect("server");
            breadcrumb!("bind_rustls .serve() returned — should never happen");
        }
        None => {
            tracing::info!("listening on {addr} (plain HTTP)");
            breadcrumb!("about to TcpListener::bind on {addr}");
            let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
            breadcrumb!("TcpListener bound, about to axum::serve");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .expect("server");
            breadcrumb!("axum::serve returned — should never happen");
        }
    }
}
