mod audit;
pub(crate) mod convert;
mod devices;
mod items;
mod orgs;
mod sessions;
mod users;
mod vaults;

use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::StorageError;

#[derive(Clone)]
pub struct PostgresStorage {
    pub(crate) pool: PgPool,
}

impl PostgresStorage {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
