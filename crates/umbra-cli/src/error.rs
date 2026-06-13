#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("toml encode error: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("missing session token; run `umbra auth token set --server-url <url> --token <token>`")]
    MissingSessionToken,
    #[error("server returned {status}: {body}")]
    ServerStatus {
        status: reqwest::StatusCode,
        body: String,
    },
}
