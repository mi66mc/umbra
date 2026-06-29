mod backend;
mod convert;
mod error;
mod models;
pub mod postgres;

#[cfg(test)]
mod tests;

pub use backend::StorageBackend;
pub use error::StorageError;
pub use models::*;
pub use postgres::PostgresStorage;

pub type Storage = PostgresStorage;
