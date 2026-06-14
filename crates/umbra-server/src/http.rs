use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
};
use chrono::{Duration, Utc};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use serde_json::{Value, json};
use tower_http::trace::TraceLayer;
use umbra_core::{MemberState, OrgRole, VaultKind, VaultRole};
use umbra_migrations::MigrationStatus;
use umbra_protocol::{
    AddOrgMemberRequest, AddVaultMemberRequest, CreateItemRequest, CreateOrgRequest,
    CreateOrgVaultRequest, CreateVaultRequest, ItemRevisionResponse, OpaqueLoginFinishRequest,
    OpaqueLoginFinishResponse, OpaqueLoginStartRequest, OpaqueLoginStartResponse,
    OpaqueRegisterFinishRequest, OpaqueRegisterStartRequest, OpaqueRegisterStartResponse,
    OrgResponse, PROTOCOL_VERSION, RotateVaultKeyRequest, RotationStatusResponse, SyncRequest,
    SyncResponse, UpdateItemRequest, VaultKeyWrappingResponse, VaultResponse, VaultSyncChanges,
};
use umbra_storage::{
    CreateDevice, CreateEncryptedItem, CreateItemRevision, CreateOrg, CreateSession, CreateUser,
    CreateVault, CreateVaultKeyWrapping, FinishVaultKeyRotation, RotationItemRevisionInput,
    UpsertOrgMember, UpsertUserAuth, UpsertVaultMember,
};
use uuid::Uuid;

use crate::authz::{
    authenticate, ensure_org_manager, ensure_org_vault_creator, ensure_vault_admin,
    ensure_vault_member, ensure_vault_writer,
};
use crate::error::ServerError;
use crate::state::{AppState, OpaqueCipherSuite, PendingLogin};
use crate::util::{decode_b64, encode_b64, ensure_protocol, random_token, token_hash};

pub(crate) fn router(state: AppState) -> Router {
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
        .route("/api/v1/sync", post(sync))
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
            auth_scheme: "bearer".to_owned(),
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

    let user_id = authenticate(&state, &headers).await?;
    ensure_vault_writer(&state, vault_id, user_id).await?;

    let revision = state
        .storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
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

    let user_id = authenticate(&state, &headers).await?;
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
    let user_id = authenticate(&state, &headers).await?;
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
