use sqlx::{PgPool, migrate::Migrator};

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

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
    MIGRATOR.run(pool).await?;
    Ok(())
}

pub async fn status(pool: &PgPool) -> Result<MigrationStatus, MigrationError> {
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

    if applied_count == MIGRATOR.iter().count() as i64 {
        Ok(MigrationStatus::Clean)
    } else {
        Ok(MigrationStatus::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_migrations() {
        assert_eq!(MIGRATOR.iter().count(), 2);
    }
}
