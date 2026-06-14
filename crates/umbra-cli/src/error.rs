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
    #[error("auth error: {0}")]
    Auth(#[from] umbra_auth::AuthError),
    #[error("missing profile `{0}`")]
    MissingProfile(String),
    #[error(
        "profile is not logged in; run `umbra login --profile <name>` or `umbra auth token set`"
    )]
    NotLoggedIn,
    #[error("invalid base64url encoding")]
    InvalidEncoding,
    #[error("opaque error: {0}")]
    Opaque(&'static str),
    #[error("input error: {0}")]
    Input(&'static str),
    #[error("prompt error: {0}")]
    Prompt(#[from] dialoguer::Error),
    #[error("server returned {status}: {body}")]
    ServerStatus {
        status: reqwest::StatusCode,
        body: String,
    },
}
