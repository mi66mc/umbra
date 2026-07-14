use std::{collections::HashMap, sync::Arc};

use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{ServerLogin, ServerSetup};
use sha2::Sha512;
use tokio::sync::Mutex;
use umbra_core::UserId;
use umbra_storage::StorageBackend;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::rate_limit::RateLimiter;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: AppConfig,
    pub(crate) storage: Arc<dyn StorageBackend>,
    pub(crate) migration_pool: MigrationPool,
    pub(crate) opaque_server_setup: Arc<ServerSetup<OpaqueCipherSuite>>,
    pub(crate) pending_logins: Arc<Mutex<HashMap<Uuid, PendingLogin>>>,
    pub(crate) rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub(crate) fn server_trusted_proxy(&self, ip: std::net::IpAddr) -> bool {
        self.config
            .server
            .trusted_proxy_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<ipnet::IpNet>().ok())
            .any(|network| network.contains(&ip))
    }
}

#[derive(Clone)]
pub(crate) enum MigrationPool {
    Postgres(sqlx::PgPool),
    Sqlite(sqlx::SqlitePool),
}

pub(crate) struct PendingLogin {
    pub(crate) user_id: UserId,
    pub(crate) server_login: ServerLogin<OpaqueCipherSuite>,
}

pub(crate) struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}
