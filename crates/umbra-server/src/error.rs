use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use umbra_storage::StorageError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ServerError {
    #[error("config error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("migration error: {0}")]
    Migration(#[from] umbra_migrations::MigrationError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("server error: {0}")]
    Serve(#[from] axum::Error),
    #[error("invalid bind address {0}")]
    InvalidBindAddress(String),
    #[error("missing opaque server setup")]
    MissingOpaqueServerSetup,
    #[error("migrations pending")]
    MigrationsPending,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(&'static str),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = match self {
            ServerError::Unauthorized => StatusCode::UNAUTHORIZED,
            ServerError::Forbidden => StatusCode::FORBIDDEN,
            ServerError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ServerError::MigrationsPending => StatusCode::SERVICE_UNAVAILABLE,
            ServerError::Storage(StorageError::NotFound) => StatusCode::NOT_FOUND,
            ServerError::Storage(StorageError::Conflict) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}
