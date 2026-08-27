use hiqlite::{params, Node, NodeConfig};

/// Shared row-mapping helper for queries that only need a single `id` column.
#[derive(Debug)]
pub struct IdRow {
    pub id: i64,
}
impl From<&mut hiqlite::Row<'_>> for IdRow {
    fn from(row: &mut hiqlite::Row<'_>) -> Self {
        Self { id: row.get("id") }
    }
}

/// Schema, split into individual statements: hiqlite's `Client::execute` runs one
/// statement at a time (no `execute_batch` like plain rusqlite/sqlx).
const SCHEMA: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        owner TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        quota_bytes INTEGER NOT NULL DEFAULT 10737418240,
        used_bytes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        expires_at TEXT
    )"#,
    r#"CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_id INTEGER REFERENCES folders(id),
        name TEXT NOT NULL,
        owner_token_id INTEGER NOT NULL REFERENCES tokens(id),
        created_at TEXT NOT NULL,
        deleted_at TEXT
    )"#,
    r#"CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder_id INTEGER REFERENCES folders(id),
        name TEXT NOT NULL,
        owner_token_id INTEGER NOT NULL REFERENCES tokens(id),
        current_version_id INTEGER,
        created_at TEXT NOT NULL,
        deleted_at TEXT
    )"#,
    r#"CREATE TABLE IF NOT EXISTS file_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL REFERENCES files(id),
        version_no INTEGER NOT NULL,
        size INTEGER NOT NULL,
        manifest TEXT NOT NULL,
        created_at TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS chunks (
        hash TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        refcount INTEGER NOT NULL DEFAULT 0
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_files_name ON files(name)",
    "CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id)",
    r#"CREATE TABLE IF NOT EXISTS shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource_type TEXT NOT NULL,
        resource_id INTEGER NOT NULL,
        owner_token_id INTEGER NOT NULL REFERENCES tokens(id),
        share_token TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        expires_at TEXT,
        permission TEXT NOT NULL,
        created_at TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource_type TEXT NOT NULL,
        resource_id INTEGER NOT NULL,
        grantee_token_id INTEGER NOT NULL,
        permission TEXT NOT NULL,
        granted_by_token_id INTEGER NOT NULL REFERENCES tokens(id),
        created_at TEXT NOT NULL
    )"#,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_resource_grantee ON permissions(resource_type, resource_id, grantee_token_id)",
    r#"CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        token_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(group_id, token_id)
    )"#,
];

/// Statements run separately from `SCHEMA`: additive `ALTER TABLE`s that error on
/// repeated startups once already applied (SQLite has no `ADD COLUMN IF NOT EXISTS`).
/// Errors from these are logged at debug and ignored rather than treated as fatal.
const ALTERS: &[&str] = &[
    "ALTER TABLE permissions ADD COLUMN grantee_group_id INTEGER",
    "ALTER TABLE tokens ADD COLUMN expires_at TEXT",
    // Public-share counters (sharing.rs). Deliberately aggregate columns on `shares` rather
    // than a per-visit log: the owner only ever needs "how much was this link used", and a
    // visit table would mean retaining IP/user-agent rows about people who specifically have
    // no account here. Nothing identifying a visitor is stored, so there is nothing to leak.
    "ALTER TABLE shares ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE shares ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE shares ADD COLUMN last_access_at TEXT",
];

/// Starts a single-node embedded hiqlite instance (no clustering) rooted at `path`,
/// and runs schema init.
///
/// ponytail: fixed loopback ports/secrets for the internal raft+api listeners hiqlite
/// still spins up even single-node; bump to env-configurable if this ever needs to run
/// more than one node or share a host with another hiqlite instance.
pub async fn init(path: &str) -> hiqlite::Client {
    let node = Node {
        id: 1,
        addr_raft: "localhost:8100".to_string(),
        addr_api: "localhost:8200".to_string(),
    };

    let config = NodeConfig {
        node_id: 1,
        nodes: vec![node],
        listen_addr_api: "127.0.0.1".into(),
        listen_addr_raft: "127.0.0.1".into(),
        data_dir: path.to_string().into(),
        secret_raft: "plaste-raft-secret-dev".to_string(),
        secret_api: "plaste-api-secret-dev".to_string(),
        ..Default::default()
    };

    let client = hiqlite::start_node(config).await.expect("hiqlite start");

    for stmt in SCHEMA {
        client.execute(*stmt, params!()).await.expect("schema init");
    }
    for stmt in ALTERS {
        if let Err(e) = client.execute(*stmt, params!()).await {
            tracing::debug!("skipping ALTER (likely already applied): {stmt}: {e}");
        }
    }

    client
}
