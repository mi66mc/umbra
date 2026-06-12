use std::{collections::HashMap, sync::Arc};

use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{ServerLogin, ServerSetup};
use sha2::Sha512;
use tokio::sync::Mutex;
use umbra_core::UserId;
use umbra_storage::Storage;
use uuid::Uuid;

use crate::config::AppConfig;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: AppConfig,
    pub(crate) storage: Storage,
    pub(crate) opaque_server_setup: Arc<ServerSetup<OpaqueCipherSuite>>,
    pub(crate) pending_logins: Arc<Mutex<HashMap<Uuid, PendingLogin>>>,
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
