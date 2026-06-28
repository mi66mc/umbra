use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{delete, get, post},
};
use chrono::{Duration, Utc};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower_http::trace::TraceLayer;
use umbra_core::{DeviceState, MemberState, OrgRole, VaultKind, VaultRole};
use umbra_crypto::{AadV1, UserPublicKey};
use umbra_migrations::MigrationStatus;
use umbra_protocol::{
    AddOrgMemberRequest, AddVaultMemberRequest, ApprovalLookupRequest, ApproveDeviceRequest,
    CreateItemRequest, CreateOrgRequest, CreateOrgVaultRequest, CreateVaultRequest,
    DeviceBootstrapResponse, DeviceResponse, ItemRevisionResponse, OpaqueLoginFinishRequest,
    OpaqueLoginFinishResponse, OpaqueLoginStartRequest, OpaqueLoginStartResponse,
    OpaqueRegisterFinishRequest, OpaqueRegisterStartRequest, OpaqueRegisterStartResponse,
    OrgResponse, PROTOCOL_VERSION, PendingDeviceResponse, PendingDeviceSummary,
    RecoverTrustRequest, RecoverTrustResponse, RecoveryChallengeStartRequest,
    RecoveryChallengeStartResponse, RotateVaultKeyRequest, RotationStatusResponse, SyncRequest,
    SyncResponse, SyncStatusRequest, SyncStatusResponse, UpdateItemRequest,
    VaultKeyWrappingResponse, VaultResponse, VaultStatus, VaultSyncChanges,
};
use umbra_storage::{
    AppendAuditLog, ApprovePendingDevice, CreateDevice, CreateEncryptedItem, CreateItemRevision,
    CreateOrg, CreateRecoveryChallenge, CreateSession, CreateUser, CreateVault,
    CreateVaultKeyWrapping, DeviceRecord, FinishVaultKeyRotation, RotationItemRevisionInput,
    UpsertOrgMember, UpsertUserAuth, UpsertVaultMember,
};
use uuid::Uuid;

use crate::authz::{
    authenticate_context, authenticate_trusted_context, ensure_org_manager,
    ensure_org_vault_creator, ensure_vault_admin, ensure_vault_member, ensure_vault_writer,
};
use crate::error::ServerError;
use crate::signed_auth::auth_middleware;
use crate::state::{AppState, OpaqueCipherSuite, PendingLogin};
use crate::util::{decode_b64, encode_b64, ensure_protocol, random_token, token_hash};

pub(crate) fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/pending", get(list_pending_devices))
        .route(
            "/api/v1/devices/approval-lookup",
            post(lookup_approval_code),
        )
        .route("/api/v1/devices/:device_id/approve", post(approve_device))
        .route("/api/v1/devices/:device_id/revoke", post(revoke_device))
        .route(
            "/api/v1/devices/:device_id/bootstrap",
            get(get_device_bootstrap),
        )
        .route(
            "/api/v1/devices/:device_id/recovery-challenge",
            post(start_recovery_challenge),
        )
        .route(
            "/api/v1/devices/:device_id/recover-trust",
            post(recover_trust),
        )
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
        .route("/api/v1/sync", post(sync))
        .route("/api/v1/sync/status", post(sync_status))
        .route("/api/v1/vaults/:vault_id/items", post(create_item))
        .route(
            "/api/v1/vaults/:vault_id/items/:item_id",
            post(update_item).put(update_item),
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
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/auth/register/start", post(auth_register_start))
        .route("/api/v1/auth/register/finish", post(auth_register_finish))
        .route("/api/v1/auth/login/start", post(auth_login_start))
        .route("/api/v1/auth/login/finish", post(auth_login_finish))
        .merge(protected)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub(crate) async fn health() -> Json<Value> {
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

fn approval_code() -> String {
    let mut compact = String::new();
    while compact.len() < 8 {
        compact.extend(
            random_token()
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .map(|ch| ch.to_ascii_uppercase())
                .take(8 - compact.len()),
        );
    }
    let first = compact.get(0..4).unwrap_or("");
    let second = compact.get(4..8).unwrap_or("");
    format!("UMBRA-{first}-{second}")
}

fn hmac_secret(state: &AppState, purpose: &str, value: &str) -> String {
    let serialized_setup;
    let key = if let Some(server_setup) = state.config.auth.opaque.server_setup.as_deref() {
        server_setup.as_bytes()
    } else {
        serialized_setup = state.opaque_server_setup.serialize();
        serialized_setup.as_slice()
    };
    encode_b64(&hmac_sha256(key, purpose.as_bytes(), value.as_bytes()))
}

fn hmac_sha256(key: &[u8], purpose: &[u8], value: &[u8]) -> [u8; 32] {
    const BLOCK_LEN: usize = 64;
    let mut key_block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for index in 0..BLOCK_LEN {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(purpose);
    inner.update([0]);
    inner.update(value);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn device_response(device: DeviceRecord) -> DeviceResponse {
    DeviceResponse {
        device_id: device.id,
        name: device.name,
        public_key: device.public_key,
        fingerprint: device.fingerprint,
        state: device.state,
        created_at: device.created_at.to_rfc3339(),
        trusted_at: device.trusted_at.map(|value| value.to_rfc3339()),
        revoked_at: device.revoked_at.map(|value| value.to_rfc3339()),
    }
}

fn pending_device_summary(device: DeviceRecord) -> Result<PendingDeviceSummary, ServerError> {
    Ok(PendingDeviceSummary {
        device_id: device.id,
        name: device.name,
        fingerprint: device.fingerprint,
        bootstrap_public_key: device.bootstrap_public_key.ok_or(ServerError::BadRequest(
            "pending device missing bootstrap public key",
        ))?,
        approval_expires_at: device
            .approval_expires_at
            .ok_or(ServerError::BadRequest(
                "pending device missing approval expiry",
            ))?
            .to_rfc3339(),
        created_at: device.created_at.to_rfc3339(),
    })
}

async fn require_trusted_current_device(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Uuid, Uuid), ServerError> {
    let auth = authenticate_trusted_context(state, headers).await?;
    let current_device_id = auth.device_id.ok_or(ServerError::Forbidden)?;
    Ok((auth.user_id, current_device_id))
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
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
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
    let expires_at = Utc::now() + Duration::minutes(state.config.security.session_ttl_minutes);
    if request.device_id.is_some() && request.pending_device.is_some() {
        return Err(ServerError::BadRequest(
            "device_id and pending_device are mutually exclusive",
        ));
    }
    let (session, session_token, auth_scheme, pending_device) = if let Some(pending_request) =
        request.pending_device
    {
        ensure_protocol(pending_request.protocol_version)?;
        let approval_code = approval_code();
        let approval_expires_at = Utc::now() + Duration::minutes(10);
        let device = state
            .storage
            .create_device(CreateDevice {
                id: None,
                user_id: user.id,
                name: pending_request.name,
                public_key: Some(pending_request.public_key),
                fingerprint: pending_request.fingerprint,
                state: DeviceState::Pending,
                approval_code_hash: Some(hmac_secret(&state, "device-approval", &approval_code)),
                approval_expires_at: Some(approval_expires_at),
                bootstrap_public_key: Some(pending_request.bootstrap_public_key),
            })
            .await?;
        let token = random_token();
        let session = state
            .storage
            .create_session(CreateSession {
                id: None,
                user_id: user.id,
                device_id: Some(device.id),
                token_hash: token_hash(&token),
                auth_scheme: "bearer".to_owned(),
                expires_at,
            })
            .await?;
        let session_id = session.id;
        (
            session,
            Some(token),
            "pending".to_owned(),
            Some(PendingDeviceResponse {
                device_id: device.id,
                session_id,
                approval_code,
                fingerprint: device.fingerprint,
                expires_at: approval_expires_at.to_rfc3339(),
            }),
        )
    } else if let Some(device_id) = request.device_id {
        let device = state.storage.find_device_by_id(device_id).await?;
        if device.user_id != user.id
            || !device.state.can_authenticate()
            || device.revoked_at.is_some()
            || device.public_key.is_none()
        {
            return Err(ServerError::Unauthorized);
        }
        let session = state
            .storage
            .create_session(CreateSession {
                id: None,
                user_id: user.id,
                device_id: Some(device_id),
                token_hash: token_hash(&random_token()),
                auth_scheme: "signed".to_owned(),
                expires_at,
            })
            .await?;
        (session, None, "signed".to_owned(), None)
    } else {
        let token = random_token();
        let session = state
            .storage
            .create_session(CreateSession {
                id: None,
                user_id: user.id,
                device_id: None,
                token_hash: token_hash(&token),
                auth_scheme: "bearer".to_owned(),
                expires_at,
            })
            .await?;
        (session, Some(token), "bearer".to_owned(), None)
    };

    Ok(Json(OpaqueLoginFinishResponse {
        user_id: user.id,
        session_id: session.id,
        session_token,
        auth_scheme,
        encrypted_private_key: user.encrypted_private_key,
        pending_device,
    }))
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceResponse>>, ServerError> {
    let auth = authenticate_trusted_context(&state, &headers).await?;
    let devices = state.storage.list_devices_for_user(auth.user_id).await?;
    Ok(Json(devices.into_iter().map(device_response).collect()))
}

async fn list_pending_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PendingDeviceSummary>>, ServerError> {
    let (user_id, _) = require_trusted_current_device(&state, &headers).await?;
    let devices = state.storage.list_pending_devices_for_user(user_id).await?;
    let summaries = devices
        .into_iter()
        .map(pending_device_summary)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(summaries))
}

async fn lookup_approval_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ApprovalLookupRequest>,
) -> Result<Json<PendingDeviceSummary>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let (user_id, _) = require_trusted_current_device(&state, &headers).await?;
    let pending = state
        .storage
        .find_pending_device_by_approval_hash(
            user_id,
            &hmac_secret(&state, "device-approval", &request.approval_code),
        )
        .await?;
    Ok(Json(pending_device_summary(pending)?))
}

async fn approve_device(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ApproveDeviceRequest>,
) -> Result<Json<DeviceResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let (user_id, current_device_id) = require_trusted_current_device(&state, &headers).await?;
    let pending = state
        .storage
        .find_pending_device_by_approval_hash(
            user_id,
            &hmac_secret(&state, "device-approval", &request.approval_code),
        )
        .await?;
    if pending.id != device_id {
        return Err(ServerError::BadRequest("device id mismatch"));
    }
    let approved = state
        .storage
        .approve_pending_device(ApprovePendingDevice {
            device_id: pending.id,
            bootstrap_bundle: request.bootstrap_bundle,
        })
        .await?;
    state
        .storage
        .append_audit_log(AppendAuditLog {
            id: None,
            actor_user_id: Some(user_id),
            vault_id: None,
            action: "device.approve".to_owned(),
            target_type: Some("device".to_owned()),
            target_id: Some(approved.id),
            metadata: json!({"approved_by_device_id": current_device_id}),
        })
        .await?;
    Ok(Json(device_response(approved)))
}

async fn revoke_device(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<DeviceResponse>, ServerError> {
    let auth = authenticate_trusted_context(&state, &headers).await?;
    let target = state.storage.find_device_by_id(device_id).await?;
    if target.user_id != auth.user_id {
        return Err(ServerError::Forbidden);
    }
    state.storage.revoke_device(device_id).await?;
    state.storage.revoke_sessions_for_device(device_id).await?;
    state
        .storage
        .append_audit_log(AppendAuditLog {
            id: None,
            actor_user_id: Some(auth.user_id),
            vault_id: None,
            action: "device.revoke".to_owned(),
            target_type: Some("device".to_owned()),
            target_id: Some(device_id),
            metadata: json!({}),
        })
        .await?;
    let revoked = state.storage.find_device_by_id(device_id).await?;
    Ok(Json(device_response(revoked)))
}

async fn get_device_bootstrap(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<DeviceBootstrapResponse>, ServerError> {
    let auth = authenticate_context(&state, &headers).await?;
    if auth.device_id != Some(device_id) {
        return Err(ServerError::Forbidden);
    }
    let device = state.storage.find_device_by_id(device_id).await?;
    if device.user_id != auth.user_id {
        return Err(ServerError::Forbidden);
    }
    Ok(Json(DeviceBootstrapResponse {
        device_id,
        state: device.state,
        bootstrap_bundle: device.bootstrap_bundle,
    }))
}

async fn start_recovery_challenge(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<RecoveryChallengeStartRequest>,
) -> Result<Json<RecoveryChallengeStartResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.device_id != device_id {
        return Err(ServerError::BadRequest("device id mismatch"));
    }
    let auth = authenticate_context(&state, &headers).await?;
    if auth.device_id != Some(device_id) {
        return Err(ServerError::Forbidden);
    }
    let device = state.storage.find_device_by_id(device_id).await?;
    if device.user_id != auth.user_id || device.state != DeviceState::Pending {
        return Err(ServerError::Forbidden);
    }
    let user = state.storage.find_user_by_id(auth.user_id).await?;
    let account_public_key = UserPublicKey::from_base64url(&user.public_key)
        .map_err(|_| ServerError::BadRequest("invalid account public key"))?;
    let challenge = random_token();
    let challenge_id = Uuid::new_v4();
    let aad = AadV1::recovery_challenge(device_id.to_string(), challenge_id.to_string());
    let encrypted =
        umbra_crypto::encrypt_recovery_challenge(&account_public_key, aad, challenge.as_bytes())
            .map_err(|_| ServerError::BadRequest("recovery challenge encryption failed"))?;
    let expires_at = Utc::now() + Duration::minutes(10);
    state
        .storage
        .create_recovery_challenge(CreateRecoveryChallenge {
            id: Some(challenge_id),
            user_id: auth.user_id,
            device_id,
            challenge_hash: hmac_secret(&state, "device-recovery-challenge", &challenge),
            expires_at,
        })
        .await?;
    Ok(Json(RecoveryChallengeStartResponse {
        challenge_id,
        encrypted_challenge: serde_json::to_value(encrypted)?,
        expires_at: expires_at.to_rfc3339(),
    }))
}

async fn recover_trust(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<RecoverTrustRequest>,
) -> Result<Json<RecoverTrustResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let auth = authenticate_context(&state, &headers).await?;
    if auth.device_id != Some(device_id) {
        return Err(ServerError::Forbidden);
    }
    state
        .storage
        .consume_recovery_challenge(
            request.challenge_id,
            auth.user_id,
            device_id,
            &hmac_secret(
                &state,
                "device-recovery-challenge",
                &request.challenge_response,
            ),
        )
        .await?;
    let trusted = state.storage.mark_device_trusted(device_id).await?;
    Ok(Json(RecoverTrustResponse {
        device_id,
        state: trusted.state,
    }))
}

async fn create_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
        request.vault_id,
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
        request.vault_id,
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
    requested_vault_id: Option<Uuid>,
    name: String,
    kind: VaultKind,
    initial_key_wrapping: Value,
) -> Result<Json<VaultResponse>, ServerError> {
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    if let Some(org_id) = org_id {
        ensure_org_vault_creator(&state, org_id, user_id).await?;
    }
    let vault = state
        .storage
        .create_vault(CreateVault {
            id: requested_vault_id,
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
    let vault = state.storage.find_vault_by_id(vault.id).await?;
    Ok(Json(vault_response(vault)))
}

async fn list_vaults(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<VaultResponse>>, ServerError> {
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    ensure_vault_admin(&state, vault_id, user_id).await?;
    state
        .storage
        .remove_vault_member(vault_id, removed_user_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(request): Json<CreateItemRequest>,
) -> Result<Json<ItemRevisionResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.vault_id != vault_id {
        return Err(ServerError::BadRequest("vault id mismatch"));
    }

    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    ensure_vault_writer(&state, vault_id, user_id).await?;

    let revision = state
        .storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: request.item_id,
            revision_id: None,
            vault_id,
            kind: request.kind,
            author_user_id: Some(user_id),
            envelope: request.envelope,
        })
        .await?;

    Ok(Json(item_revision_response(revision)))
}

async fn update_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, item_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateItemRequest>,
) -> Result<Json<ItemRevisionResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.vault_id != vault_id || request.item_id != item_id {
        return Err(ServerError::BadRequest("item path mismatch"));
    }

    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    ensure_vault_writer(&state, vault_id, user_id).await?;

    let revision = state
        .storage
        .create_item_revision(CreateItemRevision {
            revision_id: None,
            item_id,
            vault_id,
            expected_revision: request.expected_revision,
            author_user_id: Some(user_id),
            envelope: request.envelope,
        })
        .await?;

    Ok(Json(item_revision_response(revision)))
}

async fn sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    let mut vaults = Vec::with_capacity(request.vaults.len());

    for cursor in request.vaults {
        ensure_vault_member(&state, cursor.vault_id, user_id).await?;

        let vault = state.storage.find_vault_by_id(cursor.vault_id).await?;
        let items = state
            .storage
            .list_item_revisions_since(cursor.vault_id, cursor.since_vault_revision)
            .await?
            .into_iter()
            .map(item_revision_response)
            .collect();
        let key_wrappings = state
            .storage
            .list_key_wrappings_for_user_vault(user_id, cursor.vault_id)
            .await?
            .into_iter()
            .map(vault_key_wrapping_response)
            .collect();

        vaults.push(VaultSyncChanges {
            vault_id: cursor.vault_id,
            latest_vault_revision: vault.vault_revision,
            latest_access_revision: vault.access_revision,
            items,
            deleted_items: vec![],
            key_wrappings,
        });
    }

    Ok(Json(SyncResponse {
        protocol_version: PROTOCOL_VERSION,
        vaults,
    }))
}

async fn sync_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncStatusRequest>,
) -> Result<Json<SyncStatusResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    let mut vaults = Vec::with_capacity(request.vaults.len());

    for cursor in request.vaults {
        ensure_vault_member(&state, cursor.vault_id, user_id).await?;
        let status = state
            .storage
            .vault_sync_status(cursor.vault_id, user_id)
            .await?;

        vaults.push(VaultStatus {
            vault_id: status.vault_id,
            latest_vault_revision: status.latest_vault_revision,
            latest_access_revision: status.latest_access_revision,
            current_key_generation: status.current_key_generation,
            needs_key_rotation: status.needs_key_rotation,
            items_changed: status.latest_vault_revision > cursor.known_vault_revision,
            access_changed: status.latest_access_revision > cursor.known_access_revision,
        });
    }

    Ok(Json(SyncStatusResponse {
        protocol_version: PROTOCOL_VERSION,
        vaults,
    }))
}

async fn rotation_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
) -> Result<Json<RotationStatusResponse>, ServerError> {
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
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
        vault_revision: vault.vault_revision,
        access_revision: vault.access_revision,
        current_key_generation: vault.current_key_generation,
        needs_key_rotation: vault.needs_key_rotation,
    }
}

fn item_revision_response(revision: umbra_storage::ItemRevisionRecord) -> ItemRevisionResponse {
    ItemRevisionResponse {
        item_id: revision.item_id,
        vault_id: revision.vault_id,
        revision: revision.revision,
        vault_revision: revision.vault_revision,
        key_generation: revision.key_generation,
        author_user_id: revision.author_user_id,
        envelope: revision.envelope,
    }
}

fn vault_key_wrapping_response(
    wrapping: umbra_storage::VaultKeyWrappingRecord,
) -> VaultKeyWrappingResponse {
    VaultKeyWrappingResponse {
        id: wrapping.id,
        vault_id: wrapping.vault_id,
        user_id: wrapping.user_id,
        device_id: wrapping.device_id,
        wrapping_type: wrapping.wrapping_type,
        envelope: wrapping.envelope,
        key_generation: wrapping.key_generation,
    }
}
