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
    #[error("crypto error: {0}")]
    Crypto(#[from] umbra_crypto::CryptoError),
    #[error("missing profile `{0}`")]
    MissingProfile(String),
    #[error(
        "profile is not logged in; run `umbra login --profile <name>` or `umbra auth token set`"
    )]
    NotLoggedIn,
    #[error(
        "profile is missing client crypto material; run `umbra register` again for a fresh profile"
    )]
    #[allow(dead_code)]
    MissingCryptoMaterial,
    #[error("no vault key wrapping found in local cache for vault {0}")]
    #[allow(dead_code)]
    MissingVaultKeyWrapping(uuid::Uuid),
    #[error("item is not in local cache; run `umbra sync run --vault {0}` first")]
    #[allow(dead_code)]
    MissingCachedItem(uuid::Uuid),
    #[error("invalid base64url encoding")]
    InvalidEncoding,
    #[error("opaque error: {0}")]
    Opaque(&'static str),
    #[error("input error: {0}")]
    Input(&'static str),
    #[error("prompt error: {0}")]
    Prompt(#[from] dialoguer::Error),
    #[error("cache error: {0}")]
    Cache(#[from] rusqlite::Error),
    #[error("keychain error: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("profile is locked; run `umbra unlock` or enter the master password when prompted")]
    #[allow(dead_code)]
    Locked,
    #[error("local unlock state is expired; run `umbra unlock` again")]
    #[allow(dead_code)]
    UnlockExpired,
    #[error("server returned {status}: {body}")]
    ServerStatus {
        status: reqwest::StatusCode,
        body: String,
    },
}
