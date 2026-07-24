use sqlx::{PgPool, SqlitePool, migrate::Migrator};

pub const LATEST_MIGRATION_VERSION: i64 = 9;

pub static POSTGRES_MIGRATOR: Migrator = sqlx::migrate!("./migrations");
pub static SQLITE_MIGRATOR: Migrator = sqlx::migrate!("./sqlite");

pub static MIGRATOR: &Migrator = &POSTGRES_MIGRATOR;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    Unknown,
    Clean,
    Pending,
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

pub async fn run(pool: &PgPool) -> Result<(), MigrationError> {
    run_postgres(pool).await
}

pub async fn run_postgres(pool: &PgPool) -> Result<(), MigrationError> {
    POSTGRES_MIGRATOR.run(pool).await?;
    Ok(())
}

pub async fn run_sqlite(pool: &SqlitePool) -> Result<(), MigrationError> {
    SQLITE_MIGRATOR.run(pool).await?;
    Ok(())
}

pub async fn status(pool: &PgPool) -> Result<MigrationStatus, MigrationError> {
    status_postgres(pool).await
}

pub async fn status_postgres(pool: &PgPool) -> Result<MigrationStatus, MigrationError> {
    let migration_table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await?;

    if !migration_table_exists {
        return Ok(MigrationStatus::Pending);
    }

    let applied_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = true")
            .fetch_one(pool)
            .await?;

    if applied_count == POSTGRES_MIGRATOR.iter().count() as i64 {
        Ok(MigrationStatus::Clean)
    } else {
        Ok(MigrationStatus::Pending)
    }
}

pub async fn status_sqlite(pool: &SqlitePool) -> Result<MigrationStatus, MigrationError> {
    let migration_table_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_one(pool)
    .await?;

    if migration_table_exists == 0 {
        return Ok(MigrationStatus::Pending);
    }

    let applied_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = true")
            .fetch_one(pool)
            .await?;

    if applied_count == SQLITE_MIGRATOR.iter().count() as i64 {
        Ok(MigrationStatus::Clean)
    } else {
        Ok(MigrationStatus::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Executor, SqlitePool};

    #[test]
    fn embeds_postgres_and_sqlite_migrations() {
        let migrations = POSTGRES_MIGRATOR.iter().collect::<Vec<_>>();
        let sqlite_migrations = SQLITE_MIGRATOR.iter().collect::<Vec<_>>();

        assert_eq!(migrations.len(), 9);
        assert_eq!(sqlite_migrations.len(), 9);
        assert!(migrations.iter().any(|migration| {
            migration.version == 4 && migration.description == "vault access revision"
        }));
        assert!(migrations.iter().any(|migration| {
            migration.version == 5 && migration.description == "device trust state"
        }));
        assert!(sqlite_migrations.iter().any(|migration| {
            migration.version == 4 && migration.description == "vault access revision"
        }));
        assert!(sqlite_migrations.iter().any(|migration| {
            migration.version == 5 && migration.description == "device trust state"
        }));
        assert!(migrations.iter().any(|migration| {
            migration.version == 6 && migration.description == "item deletions"
        }));
        assert!(sqlite_migrations.iter().any(|migration| {
            migration.version == 6 && migration.description == "item deletions"
        }));
        assert!(migrations.iter().any(|migration| {
            migration.version == 7 && migration.description == "invite wrappings"
        }));
        assert!(sqlite_migrations.iter().any(|migration| {
            migration.version == 7 && migration.description == "invite wrappings"
        }));
        assert!(migrations.iter().any(|migration| {
            migration.version == 8 && migration.description == "item conflicts"
        }));
        assert!(sqlite_migrations.iter().any(|migration| {
            migration.version == 8 && migration.description == "item conflicts"
        }));
        assert!(migrations.iter().any(|migration| {
            migration.version == 9 && migration.description == "sync checkpoints"
        }));
        assert!(sqlite_migrations.iter().any(|migration| {
            migration.version == 9 && migration.description == "sync checkpoints"
        }));
    }

    #[tokio::test]
    async fn sqlite_invite_wrapping_migration_expires_legacy_pending_invites() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        pool.execute(include_str!("../sqlite/000001_initial_schema.sql"))
            .await
            .unwrap();
        pool.execute(include_str!(
            "../sqlite/000002_org_access_and_key_rotation.sql"
        ))
        .await
        .unwrap();
        pool.execute(include_str!("../sqlite/000003_signed_sessions.sql"))
            .await
            .unwrap();
        pool.execute(include_str!("../sqlite/000004_vault_access_revision.sql"))
            .await
            .unwrap();
        pool.execute(include_str!("../sqlite/000005_device_trust_state.sql"))
            .await
            .unwrap();
        pool.execute(include_str!("../sqlite/000006_item_deletions.sql"))
            .await
            .unwrap();

        let user_id = "00000000-0000-0000-0000-000000000001";
        let vault_id = "00000000-0000-0000-0000-000000000002";
        let stale_invite_id = "00000000-0000-0000-0000-000000000003";
        let duplicate_invite_id = "00000000-0000-0000-0000-000000000004";

        sqlx::query(
            "INSERT INTO users (id, email, display_name, public_key, encrypted_private_key) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(user_id)
        .bind("miguel@example.com")
        .bind("Miguel")
        .bind("public-key")
        .bind(r#"{"encrypted":"private-key"}"#)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO vaults (id, name, kind, created_by, crypto_policy) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(vault_id)
        .bind("Legacy Invite Vault")
        .bind("shared")
        .bind(user_id)
        .bind("{}")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO invites (id, vault_id, email, role, state, invited_by) VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
        )
        .bind(stale_invite_id)
        .bind(vault_id)
        .bind("ana@example.com")
        .bind("editor")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO invites (id, vault_id, email, role, state, invited_by) VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
        )
        .bind(duplicate_invite_id)
        .bind(vault_id)
        .bind("ANA@example.com")
        .bind("viewer")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

        pool.execute(include_str!("../sqlite/000007_invite_wrappings.sql"))
            .await
            .unwrap();

        let pending_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invites WHERE state = 'pending' AND vault_key_wrapping IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pending_count, 0);

        let expired_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invites WHERE state = 'expired' AND vault_key_wrapping IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(expired_count, 2);

        sqlx::query(
            "INSERT INTO invites (id, vault_id, email, role, state, invited_by, vault_key_wrapping) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)",
        )
        .bind("00000000-0000-0000-0000-000000000005")
        .bind(vault_id)
        .bind("ana@example.com")
        .bind("editor")
        .bind(user_id)
        .bind(r#"{"wrapped":"new"}"#)
        .execute(&pool)
        .await
        .unwrap();
    }
}
