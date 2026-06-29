mod audit;
mod backend;
mod convert;
mod devices;
mod error;
mod items;
mod models;
mod orgs;
mod sessions;
mod users;
mod vaults;

#[cfg(test)]
mod tests;

use sqlx::{PgPool, postgres::PgPoolOptions};

pub use backend::StorageBackend;
pub use error::StorageError;
pub use models::*;

#[derive(Clone)]
pub struct Storage {
    pub(crate) pool: PgPool,
}

impl Storage {
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
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
