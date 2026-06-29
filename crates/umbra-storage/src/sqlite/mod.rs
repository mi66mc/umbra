mod convert;
mod devices;
mod sessions;
mod users;

use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

use crate::StorageError;

#[derive(Clone)]
pub struct SqliteStorage {
    pub(crate) pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;

        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await?;

        Ok(Self { pool })
    }

    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
