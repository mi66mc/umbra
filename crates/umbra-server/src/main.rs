use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use config::{Config, Environment, File};
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::Mutex};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use umbra_core::{MemberState, OrgRole, UserId, VaultKind, VaultRole};
use umbra_migrations::MigrationStatus;
use umbra_protocol::{
    AddOrgMemberRequest, AddVaultMemberRequest, CreateOrgRequest, CreateOrgVaultRequest,
    CreateVaultRequest, OpaqueLoginFinishRequest, OpaqueLoginFinishResponse,
    OpaqueLoginStartRequest, OpaqueLoginStartResponse, OpaqueRegisterFinishRequest,
    OpaqueRegisterStartRequest, OpaqueRegisterStartResponse, OrgResponse, PROTOCOL_VERSION,
    RotateVaultKeyRequest, RotationStatusResponse, VaultResponse,
};
use umbra_storage::{
    CreateDevice, CreateOrg, CreateSession, CreateUser, CreateVault, CreateVaultKeyWrapping,
    FinishVaultKeyRotation, RotationItemRevisionInput, Storage, StorageError, UpsertOrgMember,
    UpsertUserAuth, UpsertVaultMember,
};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "umbra-server")]
#[command(about = "Umbra HTTP server and administration commands")]
struct Cli {
    #[arg(long, global = true)]
    config: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Migrate {
        #[command(subcommand)]
        command: Option<MigrateCommand>,
    },
    Doctor,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand)]
enum MigrateCommand {
    Status,
}

#[derive(Subcommand)]
enum ConfigCommand {
    Print,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    server: ServerSettings,
    database: DatabaseSettings,
    migrations: MigrationSettings,
    security: SecuritySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerSettings {
    bind: String,
    public_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DatabaseSettings {
    url: String,
    max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationSettings {
    auto_migrate: bool,
    require_latest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecuritySettings {
    session_ttl_minutes: i64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                bind: "127.0.0.1:8080".to_owned(),
                public_url: None,
            },
            database: DatabaseSettings {
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
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    storage: Storage,
    opaque_server_setup: Arc<ServerSetup<OpaqueCipherSuite>>,
    pending_logins: Arc<Mutex<HashMap<Uuid, PendingLogin>>>,
}

struct PendingLogin {
    user_id: UserId,
    server_login: ServerLogin<OpaqueCipherSuite>,
}

struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = load_config(cli.config.as_deref())?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config).await,
        Command::Migrate { command: None } => migrate(config).await,
        Command::Migrate {
            command: Some(MigrateCommand::Status),
        } => migrate_status(config).await,
        Command::Doctor => doctor(config).await,
        Command::Config {
            command: ConfigCommand::Print,
        } => {
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
    }
}

fn load_config(path: Option<&str>) -> Result<AppConfig, ServerError> {
    let defaults = AppConfig::default();
    let mut builder = Config::builder()
        .set_default("server.bind", defaults.server.bind)?
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

async fn connect_storage(config: &AppConfig) -> Result<Storage, ServerError> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;
    Ok(Storage::from_pool(pool))
}

async fn serve(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    if config.migrations.auto_migrate {
        umbra_migrations::run(storage.pool()).await?;
    }

    if config.migrations.require_latest
        && umbra_migrations::status(storage.pool()).await? != MigrationStatus::Clean
    {
        return Err(ServerError::MigrationsPending);
    }

    let state = AppState {
        config: config.clone(),
        storage,
        opaque_server_setup: Arc::new(ServerSetup::<OpaqueCipherSuite>::new(&mut OsRng)),
        pending_logins: Arc::new(Mutex::new(HashMap::new())),
    };

    warn!("OPAQUE server setup is generated at startup; configure persistence before production");

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

fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/auth/register/start", post(auth_register_start))
        .route("/api/v1/auth/register/finish", post(auth_register_finish))
        .route("/api/v1/auth/login/start", post(auth_login_start))
        .route("/api/v1/auth/login/finish", post(auth_login_finish))
        .route("/api/v1/orgs", post(create_org).get(list_orgs))
        .route("/api/v1/orgs/:org_id", get(get_org))
        .route(
            "/api/v1/orgs/:org_id/members",
            get(list_org_members).post(add_org_member),
        )
        .route("/api/v1/orgs/:org_id/vaults", post(create_org_vault))
        .route(
            "/api/v1/vaults",
            post(create_personal_vault).get(list_vaults),
        )
        .route("/api/v1/vaults/:vault_id/members", post(add_vault_member))
        .route(
            "/api/v1/vaults/:vault_id/members/:user_id",
            delete(remove_vault_member),
        )
        .route(
            "/api/v1/vaults/:vault_id/rotation-status",
            get(rotation_status),
        )
        .route("/api/v1/vaults/:vault_id/rotate-key", post(rotate_key))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn migrate(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    umbra_migrations::run(storage.pool()).await?;
    println!("migrations applied");
    Ok(())
}

async fn migrate_status(config: AppConfig) -> Result<(), ServerError> {
    let storage = connect_storage(&config).await?;
    println!("{:?}", umbra_migrations::status(storage.pool()).await?);
    Ok(())
}

async fn doctor(config: AppConfig) -> Result<(), ServerError> {
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
    println!("opaque_server_setup: ephemeral startup setup; not production-ready");
    println!("tls/reverse_proxy: verify externally");
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn ready(State(state): State<AppState>) -> Result<Json<Value>, ServerError> {
    let status = umbra_migrations::status(state.storage.pool()).await?;
    if status == MigrationStatus::Clean {
        Ok(Json(json!({ "status": "ready" })))
    } else {
        Err(ServerError::MigrationsPending)
    }
}

async fn auth_register_start(
    State(state): State<AppState>,
    Json(request): Json<OpaqueRegisterStartRequest>,
) -> Result<Json<OpaqueRegisterStartResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let message = RegistrationRequest::deserialize(&decode_b64(&request.registration_request)?)
        .map_err(|_| ServerError::BadRequest("invalid registration request"))?;
    let result = ServerRegistration::<OpaqueCipherSuite>::start(
        &state.opaque_server_setup,
        message,
        request.email.as_bytes(),
    )
    .map_err(|_| ServerError::BadRequest("opaque registration start failed"))?;

    Ok(Json(OpaqueRegisterStartResponse {
        registration_id: Uuid::new_v4(),
        registration_response: encode_b64(result.message.serialize().as_slice()),
    }))
}

async fn auth_register_finish(
    State(state): State<AppState>,
    Json(request): Json<OpaqueRegisterFinishRequest>,
) -> Result<Json<Value>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let upload = RegistrationUpload::<OpaqueCipherSuite>::deserialize(&decode_b64(
        &request.registration_upload,
    )?)
    .map_err(|_| ServerError::BadRequest("invalid registration upload"))?;
    let password_file = ServerRegistration::<OpaqueCipherSuite>::finish(upload);
    let auth_data = json!({
        "opaque_version": 1,
        "password_file": encode_b64(password_file.serialize().as_slice())
    });

    let user = state
        .storage
        .create_user(CreateUser {
            id: None,
            email: request.email,
            display_name: request.display_name,
            public_key: request.public_key,
            encrypted_private_key: request.encrypted_private_key,
        })
        .await?;
    state
        .storage
        .upsert_user_auth(UpsertUserAuth {
            user_id: user.id,
            auth_method: "opaque".to_owned(),
            auth_data,
        })
        .await?;
    let device = state
        .storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: request.initial_device.name,
            public_key: Some(request.initial_device.public_key),
            fingerprint: request.initial_device.fingerprint,
            trusted: true,
        })
        .await?;

    Ok(Json(json!({ "user_id": user.id, "device_id": device.id })))
}

async fn auth_login_start(
    State(state): State<AppState>,
    Json(request): Json<OpaqueLoginStartRequest>,
) -> Result<Json<OpaqueLoginStartResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user = state.storage.find_user_by_email(&request.email).await?;
    let auth = state.storage.find_user_auth(user.id).await?;
    if auth.auth_method != "opaque" {
        return Err(ServerError::Unauthorized);
    }
    let password_file_b64 = auth
        .auth_data
        .get("password_file")
        .and_then(Value::as_str)
        .ok_or(ServerError::BadRequest("missing opaque password file"))?;
    let password_file =
        ServerRegistration::<OpaqueCipherSuite>::deserialize(&decode_b64(password_file_b64)?)
            .map_err(|_| ServerError::BadRequest("invalid opaque password file"))?;
    let credential_request =
        CredentialRequest::deserialize(&decode_b64(&request.credential_request)?)
            .map_err(|_| ServerError::BadRequest("invalid credential request"))?;

    let result = ServerLogin::<OpaqueCipherSuite>::start(
        &mut OsRng,
        &state.opaque_server_setup,
        Some(password_file),
        credential_request,
        request.email.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|_| ServerError::Unauthorized)?;
    let login_id = Uuid::new_v4();
    state.pending_logins.lock().await.insert(
        login_id,
        PendingLogin {
            user_id: user.id,
            server_login: result.state,
        },
    );

    Ok(Json(OpaqueLoginStartResponse {
        login_id,
        credential_response: encode_b64(result.message.serialize().as_slice()),
    }))
}

async fn auth_login_finish(
    State(state): State<AppState>,
    Json(request): Json<OpaqueLoginFinishRequest>,
) -> Result<Json<OpaqueLoginFinishResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let pending = state
        .pending_logins
        .lock()
        .await
        .remove(&request.login_id)
        .ok_or(ServerError::Unauthorized)?;
    let finalization =
        CredentialFinalization::deserialize(&decode_b64(&request.credential_finalization)?)
            .map_err(|_| ServerError::BadRequest("invalid credential finalization"))?;
    let _finish = pending
        .server_login
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| ServerError::Unauthorized)?;
    let user = state.storage.find_user_by_id(pending.user_id).await?;
    let token = random_token();
    let expires_at = Utc::now() + Duration::minutes(state.config.security.session_ttl_minutes);
    state
        .storage
        .create_session(CreateSession {
            id: None,
            user_id: user.id,
            device_id: None,
            token_hash: token_hash(&token),
            expires_at,
        })
        .await?;

    Ok(Json(OpaqueLoginFinishResponse {
        user_id: user.id,
        session_token: token,
        encrypted_private_key: user.encrypted_private_key,
    }))
}

async fn create_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate(&state, &headers).await?;
    let org = state
        .storage
        .create_org(CreateOrg {
            id: None,
            name: request.name,
            created_by: Some(user_id),
        })
        .await?;
    state
        .storage
        .upsert_org_member(UpsertOrgMember {
            org_id: org.id,
            user_id,
            role: OrgRole::Owner,
            state: MemberState::Active,
        })
        .await?;
    Ok(Json(OrgResponse {
        org_id: org.id,
        name: org.name,
    }))
}

async fn list_orgs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OrgResponse>>, ServerError> {
    let user_id = authenticate(&state, &headers).await?;
    let orgs = state.storage.list_orgs_for_user(user_id).await?;
    Ok(Json(
        orgs.into_iter()
            .map(|org| OrgResponse {
                org_id: org.id,
                name: org.name,
            })
            .collect(),
    ))
}

async fn get_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrgResponse>, ServerError> {
    let user_id = authenticate(&state, &headers).await?;
    let member = state.storage.find_org_member(org_id, user_id).await?;
    if member.state != MemberState::Active {
        return Err(ServerError::Forbidden);
    }
    let org = state.storage.find_org_by_id(org_id).await?;
    Ok(Json(OrgResponse {
        org_id: org.id,
        name: org.name,
    }))
}

async fn list_org_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Value>, ServerError> {
    let user_id = authenticate(&state, &headers).await?;
    ensure_org_manager(&state, org_id, user_id).await?;
    let members = state.storage.list_org_members(org_id).await?;
    Ok(Json(json!(
        members
            .into_iter()
            .map(|m| json!({"user_id": m.user_id, "role": m.role, "state": m.state}))
            .collect::<Vec<_>>()
    )))
}

async fn add_org_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(request): Json<AddOrgMemberRequest>,
) -> Result<Json<Value>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate(&state, &headers).await?;
    ensure_org_manager(&state, org_id, user_id).await?;
    let member = state
        .storage
        .upsert_org_member(UpsertOrgMember {
            org_id,
            user_id: request.user_id,
            role: request.role,
            state: MemberState::Active,
        })
        .await?;
    Ok(Json(
        json!({"org_id": member.org_id, "user_id": member.user_id, "role": member.role, "state": member.state}),
    ))
}

async fn create_personal_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateVaultRequest>,
) -> Result<Json<VaultResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    create_vault_inner(
        state,
        headers,
        None,
        request.name,
        request.kind,
        request.initial_key_wrapping,
    )
    .await
}

async fn create_org_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
    Json(request): Json<CreateOrgVaultRequest>,
) -> Result<Json<VaultResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    create_vault_inner(
        state,
        headers,
        Some(org_id),
        request.name,
        request.kind,
        request.initial_key_wrapping,
    )
    .await
}

async fn create_vault_inner(
    state: AppState,
    headers: HeaderMap,
    org_id: Option<Uuid>,
    name: String,
    kind: VaultKind,
    initial_key_wrapping: Value,
) -> Result<Json<VaultResponse>, ServerError> {
    let user_id = authenticate(&state, &headers).await?;
    if let Some(org_id) = org_id {
        ensure_org_vault_creator(&state, org_id, user_id).await?;
    }
    let vault = state
        .storage
        .create_vault(CreateVault {
            id: None,
            org_id,
            name,
            kind,
            created_by: Some(user_id),
            crypto_policy: json!({}),
        })
        .await?;
    state
        .storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id,
            role: VaultRole::Owner,
            state: MemberState::Active,
        })
        .await?;
    state
        .storage
        .create_vault_key_wrapping(CreateVaultKeyWrapping {
            id: None,
            vault_id: vault.id,
            user_id,
            device_id: None,
            wrapping_type: "user_public_key".to_owned(),
            envelope: initial_key_wrapping,
            key_generation: vault.current_key_generation,
        })
        .await?;
    Ok(Json(vault_response(vault)))
}

async fn list_vaults(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<VaultResponse>>, ServerError> {
    let user_id = authenticate(&state, &headers).await?;
    let vaults = state.storage.list_vaults_for_user(user_id).await?;
    Ok(Json(vaults.into_iter().map(vault_response).collect()))
}

async fn add_vault_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(request): Json<AddVaultMemberRequest>,
) -> Result<Json<Value>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate(&state, &headers).await?;
    ensure_vault_admin(&state, vault_id, user_id).await?;
    let status = state.storage.rotation_status(vault_id).await?;
    let member = state
        .storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id,
            user_id: request.user_id,
            role: request.role,
            state: MemberState::Active,
        })
        .await?;
    state
        .storage
        .create_vault_key_wrapping(CreateVaultKeyWrapping {
            id: None,
            vault_id,
            user_id: request.user_id,
            device_id: None,
            wrapping_type: "user_public_key".to_owned(),
            envelope: request.vault_key_wrapping,
            key_generation: status.current_key_generation,
        })
        .await?;
    Ok(Json(
        json!({"vault_id": member.vault_id, "user_id": member.user_id, "role": member.role, "state": member.state}),
    ))
}

async fn remove_vault_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, removed_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ServerError> {
    let user_id = authenticate(&state, &headers).await?;
    ensure_vault_admin(&state, vault_id, user_id).await?;
    state
        .storage
        .remove_vault_member(vault_id, removed_user_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotation_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
) -> Result<Json<RotationStatusResponse>, ServerError> {
    let user_id = authenticate(&state, &headers).await?;
    ensure_vault_member(&state, vault_id, user_id).await?;
    let status = state.storage.rotation_status(vault_id).await?;
    Ok(Json(RotationStatusResponse {
        vault_id,
        current_key_generation: status.current_key_generation,
        needs_key_rotation: status.needs_key_rotation,
    }))
}

async fn rotate_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(request): Json<RotateVaultKeyRequest>,
) -> Result<Json<RotationStatusResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate(&state, &headers).await?;
    ensure_vault_admin(&state, vault_id, user_id).await?;
    let to_generation = request.to_generation;
    let status = state
        .storage
        .finish_vault_key_rotation(FinishVaultKeyRotation {
            vault_id,
            author_user_id: Some(user_id),
            from_generation: request.from_generation,
            to_generation,
            new_wrappings: request
                .new_wrappings
                .into_iter()
                .map(|w| CreateVaultKeyWrapping {
                    id: None,
                    vault_id,
                    user_id: w.user_id,
                    device_id: w.device_id,
                    wrapping_type: w.wrapping_type,
                    envelope: w.envelope,
                    key_generation: to_generation,
                })
                .collect(),
            reencrypted_revisions: request
                .reencrypted_revisions
                .into_iter()
                .map(|r| RotationItemRevisionInput {
                    revision_id: None,
                    item_id: r.item_id,
                    expected_revision: r.expected_revision,
                    envelope: r.envelope,
                })
                .collect(),
        })
        .await?;
    Ok(Json(RotationStatusResponse {
        vault_id,
        current_key_generation: status.current_key_generation,
        needs_key_rotation: status.needs_key_rotation,
    }))
}

fn vault_response(vault: umbra_storage::VaultRecord) -> VaultResponse {
    VaultResponse {
        vault_id: vault.id,
        org_id: vault.org_id,
        name: vault.name,
        kind: vault.kind,
        current_key_generation: vault.current_key_generation,
        needs_key_rotation: vault.needs_key_rotation,
    }
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<UserId, ServerError> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ServerError::Unauthorized)?;
    let session = state
        .storage
        .find_active_session_by_hash(&token_hash(token))
        .await?;
    Ok(session.user_id)
}

async fn ensure_org_manager(
    state: &AppState,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let member = state.storage.find_org_member(org_id, user_id).await?;
    if member.state == MemberState::Active && member.role.can_manage_members() {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

async fn ensure_org_vault_creator(
    state: &AppState,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let member = state.storage.find_org_member(org_id, user_id).await?;
    if member.state == MemberState::Active && member.role.can_create_vaults() {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

async fn ensure_vault_member(
    state: &AppState,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    if state
        .storage
        .has_active_vault_membership(vault_id, user_id)
        .await?
    {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

async fn ensure_vault_admin(
    state: &AppState,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let members = state.storage.list_vault_members(vault_id).await?;
    let Some(member) = members
        .into_iter()
        .find(|member| member.user_id == user_id && member.state == MemberState::Active)
    else {
        return Err(ServerError::Forbidden);
    };
    if matches!(member.role, VaultRole::Owner | VaultRole::Admin) {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}

fn ensure_protocol(version: u16) -> Result<(), ServerError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ServerError::BadRequest("unsupported protocol version"))
    }
}

fn encode_b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn decode_b64(value: &str) -> Result<Vec<u8>, ServerError> {
    Base64UrlUnpadded::decode_vec(value).map_err(|_| ServerError::BadRequest("invalid base64url"))
}

fn token_hash(token: &str) -> String {
    encode_b64(&Sha256::digest(token.as_bytes()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_b64(&bytes)
}

#[derive(Debug, thiserror::Error)]
enum ServerError {
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
