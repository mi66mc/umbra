#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("record not found")]
    NotFound,
    #[error("record conflict")]
    Conflict,
    #[error("forbidden")]
    Forbidden,
    #[error("invalid database value for {field}: {value}")]
    InvalidDatabaseValue { field: &'static str, value: String },
    #[error("operation is not supported by this storage backend: {0}")]
    UnsupportedBackendOperation(&'static str),
}

pub(crate) fn map_sqlx_error(error: sqlx::Error) -> StorageError {
    if let sqlx::Error::Database(db_error) = &error
        && db_error.is_unique_violation()
    {
        return StorageError::Conflict;
    }
    StorageError::Database(error)
}

pub(crate) fn ensure_rows_affected(rows: u64) -> Result<(), StorageError> {
    if rows == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}
