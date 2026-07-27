//! Access control: owner-or-admin always wins; otherwise defer to the `permissions`
//! table grant (read/write/comment) for this resource+grantee, direct or via group
//! membership.

use hiqlite::params;

use crate::auth::TokenCtx;
use crate::db::IdRow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Comment,
}

impl Action {
    /// Whether a stored `permissions.permission` grant covers this action.
    /// "write" implies read+comment; "comment" implies nothing extra; "read" is read-only.
    fn covered_by(self, granted: &str) -> bool {
        match granted {
            "write" => true,
            "read" => matches!(self, Action::Read),
            "comment" => matches!(self, Action::Read | Action::Comment),
            _ => false,
        }
    }
}

async fn owner_of(db: &hiqlite::Client, resource_type: &str, resource_id: i64) -> Option<i64> {
    let sql = match resource_type {
        "file" => "SELECT owner_token_id AS id FROM files WHERE id = $1 AND deleted_at IS NULL",
        "folder" => "SELECT owner_token_id AS id FROM folders WHERE id = $1 AND deleted_at IS NULL",
        _ => return None,
    };
    db.query_map_optional::<IdRow, _>(sql, params!(resource_id))
        .await
        .ok()
        .flatten()
        .map(|r| r.id)
}

/// Single entry point for all resource access checks. Admin and owner short-circuit;
/// otherwise the `permissions` table grant (if any) for this resource+grantee is fed
/// into a one-shot Casbin enforcer as the sole policy line and checked via `enforce`.
pub async fn check_access(
    db: &hiqlite::Client,
    ctx: &TokenCtx,
    resource_type: &str,
    resource_id: i64,
    action: Action,
) -> bool {
    if ctx.is_admin {
        return true;
    }

    let owner_id = match owner_of(db, resource_type, resource_id).await {
        Some(id) => id,
        None => return false, // resource doesn't exist (or already soft-deleted)
    };
    if owner_id == ctx.id {
        return true;
    }

    struct PermRow {
        permission: String,
    }
    impl From<&mut hiqlite::Row<'_>> for PermRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self {
                permission: row.get("permission"),
            }
        }
    }
    let direct_grant: Option<PermRow> = db
        .query_map_optional(
            "SELECT permission FROM permissions WHERE resource_type = $1 AND resource_id = $2 AND grantee_token_id = $3",
            params!(resource_type, resource_id, ctx.id),
        )
        .await
        .ok()
        .flatten();

    let grant = match direct_grant {
        Some(g) => Some(g),
        None => {
            // No direct token grant: check group-based grants via group_members.
            db.query_map_optional(
                "SELECT p.permission AS permission FROM permissions p \
                 JOIN group_members gm ON gm.group_id = p.grantee_group_id \
                 WHERE p.resource_type = $1 AND p.resource_id = $2 AND gm.token_id = $3 \
                 LIMIT 1",
                params!(resource_type, resource_id, ctx.id),
            )
            .await
            .ok()
            .flatten()
        }
    };

    match grant {
        Some(g) => action.covered_by(&g.permission),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiqlite::params;

    async fn test_db() -> hiqlite::Client {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        // Leak the tempdir so it outlives the client for the test's duration.
        std::mem::forget(dir);
        crate::db::init(&path).await
    }

    async fn make_token(db: &hiqlite::Client, owner: &str, is_admin: bool) -> i64 {
        let created_at = chrono::Utc::now().to_rfc3339();
        let row: IdRow = db
            .execute_returning_map_one(
                "INSERT INTO tokens (token, owner, is_admin, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
                params!(uuid::Uuid::new_v4().to_string(), owner, is_admin as i64, created_at),
            )
            .await
            .unwrap();
        row.id
    }

    fn ctx_for(id: i64, is_admin: bool) -> TokenCtx {
        TokenCtx {
            id,
            owner: format!("user{id}"),
            is_admin,
            quota_bytes: i64::MAX,
            used_bytes: 0,
            expires_at: None,
        }
    }

    async fn make_file(db: &hiqlite::Client, owner_token_id: i64) -> i64 {
        let created_at = chrono::Utc::now().to_rfc3339();
        let row: IdRow = db
            .execute_returning_map_one(
                "INSERT INTO files (name, owner_token_id, created_at) VALUES ($1, $2, $3) RETURNING id",
                params!("test.txt", owner_token_id, created_at),
            )
            .await
            .unwrap();
        row.id
    }

    #[tokio::test]
    async fn owner_has_write_access() {
        let db = test_db().await;
        let owner = make_token(&db, "owner", false).await;
        let file_id = make_file(&db, owner).await;
        let ctx = ctx_for(owner, false);
        assert!(check_access(&db, &ctx, "file", file_id, Action::Write).await);
    }

    #[tokio::test]
    async fn stranger_has_no_access() {
        let db = test_db().await;
        let owner = make_token(&db, "owner", false).await;
        let stranger = make_token(&db, "stranger", false).await;
        let file_id = make_file(&db, owner).await;
        let ctx = ctx_for(stranger, false);
        assert!(!check_access(&db, &ctx, "file", file_id, Action::Read).await);
    }

    #[tokio::test]
    async fn read_grant_allows_read_not_write() {
        let db = test_db().await;
        let owner = make_token(&db, "owner", false).await;
        let grantee = make_token(&db, "grantee", false).await;
        let file_id = make_file(&db, owner).await;
        let created_at = chrono::Utc::now().to_rfc3339();
        db.execute(
            "INSERT INTO permissions (resource_type, resource_id, grantee_token_id, permission, granted_by_token_id, created_at) VALUES ('file', $1, $2, 'read', $3, $4)",
            params!(file_id, grantee, owner, created_at),
        )
        .await
        .unwrap();

        let ctx = ctx_for(grantee, false);
        assert!(check_access(&db, &ctx, "file", file_id, Action::Read).await);
        assert!(!check_access(&db, &ctx, "file", file_id, Action::Write).await);
    }

    #[tokio::test]
    async fn admin_always_has_access() {
        let db = test_db().await;
        let owner = make_token(&db, "owner", false).await;
        let admin = make_token(&db, "admin", true).await;
        let file_id = make_file(&db, owner).await;
        let ctx = ctx_for(admin, true);
        assert!(check_access(&db, &ctx, "file", file_id, Action::Write).await);
    }

    #[tokio::test]
    async fn group_grant_covers_members_not_others() {
        let db = test_db().await;
        let owner = make_token(&db, "owner", false).await;
        let member_a = make_token(&db, "member_a", false).await;
        let member_b = make_token(&db, "member_b", false).await;
        let non_member = make_token(&db, "non_member", false).await;

        let created_at = chrono::Utc::now().to_rfc3339();
        let group: IdRow = db
            .execute_returning_map_one(
                "INSERT INTO groups (name, created_at) VALUES ($1, $2) RETURNING id",
                params!("engineering", created_at.clone()),
            )
            .await
            .unwrap();

        for member in [member_a, member_b] {
            db.execute(
                "INSERT INTO group_members (group_id, token_id, created_at) VALUES ($1, $2, $3)",
                params!(group.id, member, created_at.clone()),
            )
            .await
            .unwrap();
        }

        // Folder owned by `owner`, used as the resource being shared with the group.
        let folder: IdRow = db
            .execute_returning_map_one(
                "INSERT INTO folders (name, owner_token_id, created_at) VALUES ($1, $2, $3) RETURNING id",
                params!("shared-folder", owner, created_at.clone()),
            )
            .await
            .unwrap();

        db.execute(
            "INSERT INTO permissions (resource_type, resource_id, grantee_token_id, grantee_group_id, permission, granted_by_token_id, created_at) \
             VALUES ('folder', $1, 0, $2, 'write', $3, $4)",
            params!(folder.id, group.id, owner, created_at),
        )
        .await
        .unwrap();

        assert!(check_access(&db, &ctx_for(member_a, false), "folder", folder.id, Action::Write).await);
        assert!(check_access(&db, &ctx_for(member_b, false), "folder", folder.id, Action::Write).await);
        assert!(!check_access(&db, &ctx_for(non_member, false), "folder", folder.id, Action::Write).await);
    }
}
