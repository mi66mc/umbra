use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tokio::{net::TcpListener, sync::Mutex};
use tracing::{info, warn};
use umbra_migrations::MigrationStatus;
use umbra_storage::{PostgresStorage, SqliteStorage, StorageBackend};

use crate::config::{AppConfig, DatabaseBackend};
use crate::error::ServerError;
use crate::http::router;
use crate::rate_limit::RateLimiter;
use crate::state::{AppState, MigrationPool};
use crate::util::opaque_server_setup_from_config;

pub(crate) enum ConnectedStorage {
    Postgres(PostgresStorage),
    Sqlite(SqliteStorage),
}

impl ConnectedStorage {
    pub(crate) fn backend(self) -> Arc<dyn StorageBackend> {
        match self {
            ConnectedStorage::Postgres(storage) => Arc::new(storage),
            ConnectedStorage::Sqlite(storage) => Arc::new(storage),
        }
    }

    pub(crate) fn migration_pool(&self) -> MigrationPool {
        match self {
            ConnectedStorage::Postgres(storage) => MigrationPool::Postgres(storage.pool().clone()),
            ConnectedStorage::Sqlite(storage) => MigrationPool::Sqlite(storage.pool().clone()),
        }
    }
}

pub(crate) async fn connect_storage(config: &AppConfig) -> Result<ConnectedStorage, ServerError> {
    match config.database.backend {
        DatabaseBackend::Postgres => Ok(ConnectedStorage::Postgres(
            PostgresStorage::connect(&config.database.url, config.database.max_connections).await?,
        )),
        DatabaseBackend::Sqlite => Ok(ConnectedStorage::Sqlite(
            SqliteStorage::connect(&config.database.url, config.database.max_connections).await?,
        )),
    }
}

pub(crate) async fn run_migrations(storage: &ConnectedStorage) -> Result<(), ServerError> {
    match storage {
        ConnectedStorage::Postgres(storage) => {
            umbra_migrations::run_postgres(storage.pool()).await?
        }
        ConnectedStorage::Sqlite(storage) => umbra_migrations::run_sqlite(storage.pool()).await?,
    }
    Ok(())
}

pub(crate) async fn migration_status(
    storage: &ConnectedStorage,
) -> Result<MigrationStatus, ServerError> {
    Ok(match storage {
        ConnectedStorage::Postgres(storage) => {
            umbra_migrations::status_postgres(storage.pool()).await?
        }
        ConnectedStorage::Sqlite(storage) => {
            umbra_migrations::status_sqlite(storage.pool()).await?
        }
    })
}

pub(crate) async fn serve(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    if config.migrations.auto_migrate {
        run_migrations(&storage).await?;
    }

    if config.migrations.require_latest
        && migration_status(&storage).await? != MigrationStatus::Clean
    {
        return Err(ServerError::MigrationsPending);
    }

    let opaque_setup = opaque_server_setup_from_config(&config)?;
    let migration_pool = storage.migration_pool();
    let storage = storage.backend();
    let state = AppState {
        config: config.clone(),
        storage,
        migration_pool,
        opaque_server_setup: Arc::new(opaque_setup),
        pending_logins: Arc::new(Mutex::new(HashMap::new())),
        rate_limiter: Arc::new(RateLimiter::default()),
    };

    if config.auth.opaque.server_setup.is_none() {
        warn!(
            "OPAQUE server setup is ephemeral; configure auth.opaque.server_setup before production"
        );
    }

    let app = router(state);
    let addr: SocketAddr = config
        .server
        .bind
        .parse()
        .map_err(|_| ServerError::InvalidBindAddress(config.server.bind.clone()))?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "umbra-server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

pub(crate) async fn migrate(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    run_migrations(&storage).await?;
    println!("migrations applied");
    Ok(())
}

pub(crate) async fn migrate_status(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    println!("{:?}", migration_status(&storage).await?);
    Ok(())
}

pub(crate) async fn doctor(
    config: AppConfig,
    json_output: bool,
    strict: bool,
) -> Result<(), ServerError> {
    let mut warnings = Vec::new();
    let bind: SocketAddr = config
        .server
        .bind
        .parse()
        .map_err(|_| ServerError::InvalidBindAddress(config.server.bind.clone()))?;
    let bind_public = !bind.ip().is_loopback() && !bind.ip().is_unspecified();
    let public_url = config.server.public_url.as_deref();
    if public_url.is_none() {
        warnings.push("public_url is missing".to_owned());
    }
    if public_url.is_some_and(|url| url.starts_with("http://") && !is_loopback_http_url(url)) {
        warnings.push("public_url uses insecure HTTP".to_owned());
    }
    if bind_public && !public_url.is_some_and(|url| url.starts_with("https://")) {
        warnings.push("public bind requires an HTTPS public_url".to_owned());
    }
    if config.migrations.auto_migrate {
        warnings.push("auto_migrate is enabled".to_owned());
    }
    if !config.migrations.require_latest {
        warnings.push("require_latest is disabled".to_owned());
    }
    let opaque = if config.auth.opaque.server_setup.is_some() {
        "persistent"
    } else if config.auth.opaque.allow_ephemeral_setup {
        warnings.push("OPAQUE server setup is ephemeral".to_owned());
        "ephemeral"
    } else {
        warnings.push("OPAQUE server setup is missing".to_owned());
        "missing"
    };
    for cidr in &config.server.trusted_proxy_cidrs {
        cidr.parse::<ipnet::IpNet>().map_err(|_| {
            ServerError::UnsafeConfiguration(format!("invalid trusted proxy CIDR: {cidr}"))
        })?;
    }
    let storage = connect_storage(&config).await?;
    let migration = migration_status(&storage).await?;
    if migration != MigrationStatus::Clean {
        warnings.push("migrations are pending".to_owned());
    }
    if strict && !warnings.is_empty() {
        return Err(ServerError::UnsafeConfiguration(warnings.join("; ")));
    }
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "database": "ok", "migrations": format!("{migration:?}"), "opaque_server_setup": opaque,
                "public_url": public_url, "trusted_proxy_cidrs": config.server.trusted_proxy_cidrs,
                "warnings": warnings, "strict": strict
            })
        );
    } else {
        println!("database: ok");
        println!("migrations: {migration:?}");
        println!("opaque_server_setup: {opaque}");
        println!(
            "trusted_proxy_cidrs: {}",
            config.server.trusted_proxy_cidrs.len()
        );
        for warning in warnings {
            println!("warning: {warning}");
        }
    }
    Ok(())
}

fn is_loopback_http_url(url: &str) -> bool {
    let host = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}
