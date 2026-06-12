use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{info, warn};
use umbra_migrations::MigrationStatus;
use umbra_storage::Storage;

use crate::config::AppConfig;
use crate::error::ServerError;
use crate::http::router;
use crate::state::AppState;
use crate::util::opaque_server_setup_from_config;

pub(crate) async fn connect_storage(config: &AppConfig) -> Result<Storage, ServerError> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;
    Ok(Storage::from_pool(pool))
}

pub(crate) async fn serve(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    if config.migrations.auto_migrate {
        umbra_migrations::run(storage.pool()).await?;
    }

    if config.migrations.require_latest
        && umbra_migrations::status(storage.pool()).await? != MigrationStatus::Clean
    {
        return Err(ServerError::MigrationsPending);
    }

    let opaque_setup = opaque_server_setup_from_config(&config)?;
    let state = AppState {
        config: config.clone(),
        storage,
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
    umbra_migrations::run(storage.pool()).await?;
    println!("migrations applied");
    Ok(())
}

pub(crate) async fn migrate_status(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    println!("{:?}", umbra_migrations::status(storage.pool()).await?);
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
    println!(
        "migrations: {:?}",
        umbra_migrations::status(storage.pool()).await?
    );
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
