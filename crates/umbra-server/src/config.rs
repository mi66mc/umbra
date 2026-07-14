use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};

use crate::error::ServerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AppConfig {
    pub(crate) server: ServerSettings,
    pub(crate) database: DatabaseSettings,
    pub(crate) migrations: MigrationSettings,
    pub(crate) security: SecuritySettings,
    pub(crate) auth: AuthSettings,
    #[serde(default)]
    pub(crate) rate_limit: RateLimitSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ServerSettings {
    pub(crate) bind: String,
    pub(crate) public_url: Option<String>,
    #[serde(default)]
    pub(crate) trusted_proxy_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabaseSettings {
    pub(crate) backend: DatabaseBackend,
    pub(crate) url: String,
    pub(crate) max_connections: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DatabaseBackend {
    Postgres,
    Sqlite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MigrationSettings {
    pub(crate) auto_migrate: bool,
    pub(crate) require_latest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SecuritySettings {
    pub(crate) session_ttl_minutes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RateLimitSettings {
    pub(crate) registration_per_hour: u32,
    pub(crate) auth_per_minute: u32,
    pub(crate) authenticated_per_minute: u32,
    pub(crate) write_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthSettings {
    pub(crate) opaque: OpaqueSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OpaqueSettings {
    pub(crate) server_setup: Option<String>,
    pub(crate) allow_ephemeral_setup: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                bind: "127.0.0.1:8080".to_owned(),
                public_url: None,
                trusted_proxy_cidrs: Vec::new(),
            },
            database: DatabaseSettings {
                backend: DatabaseBackend::Postgres,
                url: "postgres://umbra:umbra@localhost:5432/umbra".to_owned(),
                max_connections: 10,
            },
            migrations: MigrationSettings {
                auto_migrate: false,
                require_latest: true,
            },
            security: SecuritySettings {
                session_ttl_minutes: 60,
            },
            auth: AuthSettings {
                opaque: OpaqueSettings {
                    server_setup: None,
                    allow_ephemeral_setup: false,
                },
            },
            rate_limit: RateLimitSettings {
                registration_per_hour: 3,
                auth_per_minute: 5,
                authenticated_per_minute: 120,
                write_per_minute: 30,
            },
        }
    }
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        AppConfig::default().rate_limit
    }
}

pub(crate) fn load_config(path: Option<&str>) -> Result<AppConfig, ServerError> {
    let defaults = AppConfig::default();
    let mut builder = Config::builder()
        .set_default("server.bind", defaults.server.bind)?
        .set_default("database.backend", "postgres")?
        .set_default("database.url", defaults.database.url)?
        .set_default(
            "database.max_connections",
            defaults.database.max_connections,
        )?
        .set_default("migrations.auto_migrate", defaults.migrations.auto_migrate)?
        .set_default(
            "migrations.require_latest",
            defaults.migrations.require_latest,
        )?
        .set_default(
            "security.session_ttl_minutes",
            defaults.security.session_ttl_minutes,
        )?
        .set_default(
            "auth.opaque.allow_ephemeral_setup",
            defaults.auth.opaque.allow_ephemeral_setup,
        )?
        .set_default(
            "rate_limit.registration_per_hour",
            defaults.rate_limit.registration_per_hour,
        )?
        .set_default(
            "rate_limit.auth_per_minute",
            defaults.rate_limit.auth_per_minute,
        )?
        .set_default(
            "rate_limit.authenticated_per_minute",
            defaults.rate_limit.authenticated_per_minute,
        )?
        .set_default(
            "rate_limit.write_per_minute",
            defaults.rate_limit.write_per_minute,
        )?;

    if let Some(path) = path {
        builder = builder.add_source(File::with_name(path).required(false));
    } else {
        builder = builder.add_source(File::with_name("umbra-server.toml").required(false));
    }

    builder
        .add_source(Environment::with_prefix("UMBRA").separator("__"))
        .build()?
        .try_deserialize()
        .map_err(ServerError::from)
}
