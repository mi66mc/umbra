use sqlx::{PgPool, SqlitePool, migrate::Migrator};

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

    #[test]
    fn embeds_postgres_and_sqlite_migrations() {
        let migrations = POSTGRES_MIGRATOR.iter().collect::<Vec<_>>();
        let sqlite_migrations = SQLITE_MIGRATOR.iter().collect::<Vec<_>>();

        assert_eq!(migrations.len(), 5);
        assert_eq!(sqlite_migrations.len(), 5);
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
    }
}
