use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::{net::TcpListener, sync::Mutex};
use tracing::{info, warn};
use umbra_migrations::MigrationStatus;
use umbra_storage::{PostgresStorage, SqliteStorage, StorageBackend};

use crate::config::{AppConfig, DatabaseBackend};
use crate::error::ServerError;
use crate::http::router;
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
    axum::serve(listener, app).await?;
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

pub(crate) async fn doctor(config: AppConfig) -> Result<(), ServerError> {
    println!("config: ok");
    if config.server.public_url.is_none() {
        println!("public_url: missing");
    } else {
        println!("public_url: ok");
    }

    let storage = connect_storage(&config).await?;
    println!("database: ok");
    println!("migrations: {:?}", migration_status(&storage).await?);
    if config.auth.opaque.server_setup.is_some() {
        println!("opaque_server_setup: persistent");
    } else if config.auth.opaque.allow_ephemeral_setup {
        println!("opaque_server_setup: ephemeral");
    } else {
        println!("opaque_server_setup: missing");
    }
    println!("tls/reverse_proxy: verify externally");
    Ok(())
}
