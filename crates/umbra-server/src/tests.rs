use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::IntoResponse,
};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serial_test::serial;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower::ServiceExt;
use umbra_auth::{
    HEADER_BODY_SHA256, HEADER_DEVICE_ID, HEADER_NONCE, HEADER_SESSION_ID, HEADER_SIGNATURE,
    HEADER_TIMESTAMP, SignedRequestParts, body_sha256_b64, sign_request, verifying_key_to_b64,
};
use umbra_core::{VaultKind, VaultRole};
use umbra_protocol::{
    AddVaultMemberRequest, CreateItemRequest, CreateOrgRequest, CreateVaultRequest,
    DeviceRegisterRequest, ItemRevisionResponse, OpaqueLoginFinishRequest,
    OpaqueLoginFinishResponse, OpaqueLoginStartRequest, OpaqueLoginStartResponse,
    OpaqueRegisterFinishRequest, OpaqueRegisterStartRequest, OpaqueRegisterStartResponse,
    OrgResponse, PROTOCOL_VERSION, RegisterResponse, SyncRequest, SyncResponse, SyncStatusRequest,
    SyncStatusResponse, UpdateItemRequest, VaultResponse, VaultStatusCursor, VaultSyncCursor,
};
use umbra_storage::Storage;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::ServerError;
use crate::http::{health, router};
use crate::state::{AppState, OpaqueCipherSuite};
use crate::util::{
    decode_b64, encode_b64, generate_opaque_server_setup_secret, opaque_server_setup_from_config,
    opaque_server_setup_from_secret,
};

#[test]
fn opaque_setup_secret_roundtrips() {
    let secret = generate_opaque_server_setup_secret();
    let setup = opaque_server_setup_from_secret(&secret).expect("generated secret is valid");
    let encoded = encode_b64(setup.serialize().as_slice());

    assert_eq!(secret, encoded);
}

#[test]
fn production_config_requires_persistent_opaque_setup() {
    let config = AppConfig::default();

    let err = opaque_server_setup_from_config(&config).unwrap_err();

    assert!(matches!(err, ServerError::MissingOpaqueServerSetup));
}

#[test]
fn dev_config_can_use_ephemeral_opaque_setup_when_explicitly_allowed() {
    let mut config = AppConfig::default();
    config.auth.opaque.allow_ephemeral_setup = true;

    opaque_server_setup_from_config(&config).expect("dev ephemeral setup is allowed");
}

#[tokio::test]
async fn health_responds_without_database_query() {
    let response = health().await.into_response();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[serial(postgres)]
async fn opaque_login_token_can_create_org_and_personal_vault() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let email = "miguel@example.com";
    let password = b"correct horse battery staple";

    let token = register_and_login(app.clone(), email, password).await;

    let (status, org): (StatusCode, OrgResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/orgs",
        Some(&token),
        &CreateOrgRequest {
            protocol_version: PROTOCOL_VERSION,
            name: "BlackWire".to_owned(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(org.name, "BlackWire");

    let (status, vault): (StatusCode, VaultResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Personal".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(vault.org_id, None);
    assert_eq!(vault.vault_revision, 0);
    assert!(vault.access_revision > 0);
    assert_eq!(vault.current_key_generation, 1);
}

#[tokio::test]
#[serial(postgres)]
async fn create_vault_returns_client_supplied_id() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let token = register_and_login(app.clone(), "vault-id@example.com", b"vault id password").await;
    let requested_vault_id = Uuid::new_v4();

    let (status, vault): (StatusCode, VaultResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: Some(requested_vault_id),
            name: "Bound Vault".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(vault.vault_id, requested_vault_id);
    assert_eq!(vault.vault_revision, 0);
    assert!(vault.access_revision > 0);
}

#[tokio::test]
#[serial(postgres)]
async fn viewer_cannot_create_item() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));

    let owner_token = register_and_login(app.clone(), "owner@example.com", b"owner password").await;
    let viewer_token =
        register_and_login(app.clone(), "viewer@example.com", b"viewer password").await;

    let (_status, owner_vault): (StatusCode, VaultResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&owner_token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Shared".to_owned(),
            kind: VaultKind::Shared,
            initial_key_wrapping: json!({"owner": true}),
        },
    )
    .await;

    let viewer_user_id = login_user_id(app.clone(), "viewer@example.com", b"viewer password").await;
    let (status, _body): (StatusCode, serde_json::Value) = json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/members", owner_vault.vault_id),
        Some(&owner_token),
        &AddVaultMemberRequest {
            protocol_version: PROTOCOL_VERSION,
            user_id: viewer_user_id,
            role: VaultRole::Viewer,
            vault_key_wrapping: json!({"viewer": true}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _body): (StatusCode, serde_json::Value) = json_request(
        app,
        Method::POST,
        &format!("/api/v1/vaults/{}/items", owner_vault.vault_id),
        Some(&viewer_token),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: owner_vault.vault_id,
            item_id: None,
            kind: umbra_core::ItemKind::ApiKey,
            envelope: json!({"ciphertext": "viewer-write"}),
        },
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(postgres)]
async fn owner_can_create_update_and_sync_item_revisions() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let token = register_and_login(app.clone(), "items@example.com", b"items password").await;

    let (_status, vault): (StatusCode, VaultResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Personal".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;

    let (status, created): (StatusCode, ItemRevisionResponse) = json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/items", vault.vault_id),
        Some(&token),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id: None,
            kind: umbra_core::ItemKind::ApiKey,
            envelope: json!({"ciphertext": "v1"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.revision, 1);
    assert_eq!(created.vault_revision, 1);

    let (status, updated): (StatusCode, ItemRevisionResponse) = json_request(
        app.clone(),
        Method::PUT,
        &format!(
            "/api/v1/vaults/{}/items/{}",
            vault.vault_id, created.item_id
        ),
        Some(&token),
        &UpdateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id: created.item_id,
            expected_revision: 1,
            envelope: json!({"ciphertext": "v2"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated.revision, 2);
    assert_eq!(updated.vault_revision, 2);

    let (status, sync): (StatusCode, SyncResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/sync",
        Some(&token),
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id: uuid::Uuid::new_v4(),
            vaults: vec![VaultSyncCursor {
                vault_id: vault.vault_id,
                since_vault_revision: 0,
            }],
        },
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync.protocol_version, PROTOCOL_VERSION);
    assert_eq!(sync.vaults.len(), 1);
    assert_eq!(sync.vaults[0].latest_vault_revision, 2);
    assert_eq!(sync.vaults[0].latest_access_revision, 2);
    assert_eq!(sync.vaults[0].items.len(), 2);
    assert_eq!(
        sync.vaults[0].items[0].envelope,
        json!({"ciphertext": "v1"})
    );
    assert_eq!(
        sync.vaults[0].items[1].envelope,
        json!({"ciphertext": "v2"})
    );
    assert_eq!(sync.vaults[0].key_wrappings.len(), 1);
}

#[tokio::test]
#[serial(postgres)]
async fn sync_status_reports_item_changes() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let token = register_and_login(app.clone(), "sync-status@example.com", b"sync status").await;
    let non_member_token = register_and_login(
        app.clone(),
        "sync-status-other@example.com",
        b"sync status other",
    )
    .await;

    let (_status, vault): (StatusCode, VaultResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Status".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;

    let (status, created): (StatusCode, ItemRevisionResponse) = json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/items", vault.vault_id),
        Some(&token),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id: None,
            kind: umbra_core::ItemKind::ApiKey,
            envelope: json!({"ciphertext": "v1"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.vault_revision, 1);

    let status_request = SyncStatusRequest {
        protocol_version: PROTOCOL_VERSION,
        vaults: vec![VaultStatusCursor {
            vault_id: vault.vault_id,
            known_vault_revision: 0,
            known_access_revision: 0,
        }],
    };
    let (status, sync_status): (StatusCode, SyncStatusResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/sync/status",
        Some(&token),
        &status_request,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync_status.protocol_version, PROTOCOL_VERSION);
    assert_eq!(sync_status.vaults.len(), 1);
    assert_eq!(sync_status.vaults[0].vault_id, vault.vault_id);
    assert_eq!(sync_status.vaults[0].latest_vault_revision, 1);
    assert_eq!(sync_status.vaults[0].latest_access_revision, 2);
    assert_eq!(sync_status.vaults[0].current_key_generation, 1);
    assert!(!sync_status.vaults[0].needs_key_rotation);
    assert!(sync_status.vaults[0].items_changed);
    assert!(sync_status.vaults[0].access_changed);

    let (status, unchanged): (StatusCode, SyncStatusResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/sync/status",
        Some(&token),
        &SyncStatusRequest {
            protocol_version: PROTOCOL_VERSION,
            vaults: vec![VaultStatusCursor {
                vault_id: vault.vault_id,
                known_vault_revision: sync_status.vaults[0].latest_vault_revision,
                known_access_revision: sync_status.vaults[0].latest_access_revision,
            }],
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!unchanged.vaults[0].items_changed);
    assert!(!unchanged.vaults[0].access_changed);

    let (status, _body): (StatusCode, serde_json::Value) = json_request(
        app,
        Method::POST,
        "/api/v1/sync/status",
        Some(&non_member_token),
        &status_request,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(postgres)]
async fn create_item_returns_client_supplied_id() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let token = register_and_login(app.clone(), "item-id@example.com", b"item id password").await;

    let (_status, vault): (StatusCode, VaultResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Personal".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;
    let requested_item_id = Uuid::new_v4();

    let (status, created): (StatusCode, ItemRevisionResponse) = json_request(
        app,
        Method::POST,
        &format!("/api/v1/vaults/{}/items", vault.vault_id),
        Some(&token),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id: Some(requested_item_id),
            kind: umbra_core::ItemKind::ApiKey,
            envelope: json!({"ciphertext": "v1"}),
        },
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.item_id, requested_item_id);
}

#[tokio::test]
#[serial(postgres)]
async fn signed_login_can_create_org_and_rejects_nonce_replay() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let email = "signed-login@example.com";
    let password = b"signed login password";

    let registration_start =
        ClientRegistration::<OpaqueCipherSuite>::start(&mut OsRng, password).unwrap();
    let (status, start_response): (StatusCode, OpaqueRegisterStartResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/register/start",
        None,
        &OpaqueRegisterStartRequest {
            protocol_version: PROTOCOL_VERSION,
            email: email.to_owned(),
            registration_request: encode_b64(registration_start.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let registration_response = RegistrationResponse::<OpaqueCipherSuite>::deserialize(
        &decode_b64(&start_response.registration_response).unwrap(),
    )
    .unwrap();
    let registration_finish = registration_start
        .state
        .finish(
            &mut OsRng,
            password,
            registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let (status, register): (StatusCode, RegisterResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/register/finish",
        None,
        &OpaqueRegisterFinishRequest {
            protocol_version: PROTOCOL_VERSION,
            registration_id: start_response.registration_id,
            email: email.to_owned(),
            display_name: Some("Signed".to_owned()),
            public_key: "user-public-key".to_owned(),
            encrypted_private_key: json!({"ciphertext": "private"}),
            initial_device: DeviceRegisterRequest {
                name: "signed laptop".to_owned(),
                public_key: verifying_key_to_b64(&signing_key.verifying_key()),
                fingerprint: "signed-device-fingerprint".to_owned(),
            },
            registration_upload: encode_b64(registration_finish.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let login_start = ClientLogin::<OpaqueCipherSuite>::start(&mut OsRng, password).unwrap();
    let (status, login_response): (StatusCode, OpaqueLoginStartResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/login/start",
        None,
        &OpaqueLoginStartRequest {
            protocol_version: PROTOCOL_VERSION,
            email: email.to_owned(),
            credential_request: encode_b64(login_start.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let credential_response = CredentialResponse::<OpaqueCipherSuite>::deserialize(
        &decode_b64(&login_response.credential_response).unwrap(),
    )
    .unwrap();
    let login_finish = login_start
        .state
        .finish(
            &mut OsRng,
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let (status, finish): (StatusCode, OpaqueLoginFinishResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/login/finish",
        None,
        &OpaqueLoginFinishRequest {
            protocol_version: PROTOCOL_VERSION,
            login_id: login_response.login_id,
            device_id: Some(register.device_id),
            pending_device: None,
            credential_finalization: encode_b64(login_finish.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(finish.auth_scheme, "signed");
    assert_eq!(finish.session_token, None);

    let nonce = Uuid::new_v4().to_string();
    let (status, org): (StatusCode, OrgResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        "/api/v1/orgs",
        SignedRequestAuth {
            session_id: finish.session_id,
            device_id: register.device_id,
            signing_key: &signing_key,
            nonce: &nonce,
        },
        &CreateOrgRequest {
            protocol_version: PROTOCOL_VERSION,
            name: "Signed Org".to_owned(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(org.name, "Signed Org");

    let (status, _body): (StatusCode, serde_json::Value) = signed_json_request(
        app,
        Method::POST,
        "/api/v1/orgs",
        SignedRequestAuth {
            session_id: finish.session_id,
            device_id: register.device_id,
            signing_key: &signing_key,
            nonce: &nonce,
        },
        &CreateOrgRequest {
            protocol_version: PROTOCOL_VERSION,
            name: "Replay Org".to_owned(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn register_and_login(app: Router, email: &str, password: &[u8]) -> String {
    let registration_start =
        ClientRegistration::<OpaqueCipherSuite>::start(&mut OsRng, password).unwrap();
    let (status, start_response): (StatusCode, OpaqueRegisterStartResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/register/start",
        None,
        &OpaqueRegisterStartRequest {
            protocol_version: PROTOCOL_VERSION,
            email: email.to_owned(),
            registration_request: encode_b64(registration_start.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let registration_response = RegistrationResponse::<OpaqueCipherSuite>::deserialize(
        &decode_b64(&start_response.registration_response).unwrap(),
    )
    .unwrap();
    let registration_finish = registration_start
        .state
        .finish(
            &mut OsRng,
            password,
            registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let (status, _register): (StatusCode, RegisterResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/register/finish",
        None,
        &OpaqueRegisterFinishRequest {
            protocol_version: PROTOCOL_VERSION,
            registration_id: start_response.registration_id,
            email: email.to_owned(),
            display_name: Some("Miguel".to_owned()),
            public_key: "user-public-key".to_owned(),
            encrypted_private_key: json!({"ciphertext": "private"}),
            initial_device: DeviceRegisterRequest {
                name: "dev laptop".to_owned(),
                public_key: "device-public-key".to_owned(),
                fingerprint: "device-fingerprint".to_owned(),
            },
            registration_upload: encode_b64(registration_finish.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let login_start = ClientLogin::<OpaqueCipherSuite>::start(&mut OsRng, password).unwrap();
    let (status, login_response): (StatusCode, OpaqueLoginStartResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/login/start",
        None,
        &OpaqueLoginStartRequest {
            protocol_version: PROTOCOL_VERSION,
            email: email.to_owned(),
            credential_request: encode_b64(login_start.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let credential_response = CredentialResponse::<OpaqueCipherSuite>::deserialize(
        &decode_b64(&login_response.credential_response).unwrap(),
    )
    .unwrap();
    let login_finish = login_start
        .state
        .finish(
            &mut OsRng,
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let (status, finish): (StatusCode, OpaqueLoginFinishResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/auth/login/finish",
        None,
        &OpaqueLoginFinishRequest {
            protocol_version: PROTOCOL_VERSION,
            login_id: login_response.login_id,
            device_id: None,
            pending_device: None,
            credential_finalization: encode_b64(login_finish.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    finish
        .session_token
        .expect("legacy bearer login returns a session token")
}

async fn login_user_id(app: Router, email: &str, password: &[u8]) -> uuid::Uuid {
    let login_start = ClientLogin::<OpaqueCipherSuite>::start(&mut OsRng, password).unwrap();
    let (status, login_response): (StatusCode, OpaqueLoginStartResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/login/start",
        None,
        &OpaqueLoginStartRequest {
            protocol_version: PROTOCOL_VERSION,
            email: email.to_owned(),
            credential_request: encode_b64(login_start.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let credential_response = CredentialResponse::<OpaqueCipherSuite>::deserialize(
        &decode_b64(&login_response.credential_response).unwrap(),
    )
    .unwrap();
    let login_finish = login_start
        .state
        .finish(
            &mut OsRng,
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let (status, finish): (StatusCode, OpaqueLoginFinishResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/auth/login/finish",
        None,
        &OpaqueLoginFinishRequest {
            protocol_version: PROTOCOL_VERSION,
            login_id: login_response.login_id,
            device_id: None,
            pending_device: None,
            credential_finalization: encode_b64(login_finish.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    finish.user_id
}

struct SignedRequestAuth<'a> {
    session_id: Uuid,
    device_id: Uuid,
    signing_key: &'a ed25519_dalek::SigningKey,
    nonce: &'a str,
}

async fn json_request<T, R>(
    app: Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: &T,
) -> (StatusCode, R)
where
    T: Serialize,
    R: for<'de> Deserialize<'de>,
{
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, serde_json::from_value(body).unwrap())
}

async fn signed_json_request<T, R>(
    app: Router,
    method: Method,
    uri: &str,
    auth: SignedRequestAuth<'_>,
    body: &T,
) -> (StatusCode, R)
where
    T: Serialize,
    R: for<'de> Deserialize<'de>,
{
    let body_bytes = serde_json::to_vec(body).unwrap();
    let timestamp_unix = chrono::Utc::now().timestamp();
    let body_hash = body_sha256_b64(&body_bytes);
    let parts = SignedRequestParts {
        method: method.as_str().to_owned(),
        path_and_query: uri.to_owned(),
        body_sha256: body_hash.clone(),
        timestamp_unix,
        nonce: auth.nonce.to_owned(),
        session_id: auth.session_id,
        device_id: auth.device_id,
    };
    let signature = sign_request(auth.signing_key, &parts);
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(HEADER_SESSION_ID, auth.session_id.to_string())
                .header(HEADER_DEVICE_ID, auth.device_id.to_string())
                .header(HEADER_TIMESTAMP, timestamp_unix.to_string())
                .header(HEADER_NONCE, auth.nonce)
                .header(HEADER_BODY_SHA256, body_hash)
                .header(HEADER_SIGNATURE, signature)
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, serde_json::from_value(body).unwrap())
}

fn test_state_with_storage(storage: Storage) -> AppState {
    let mut config = AppConfig::default();
    config.auth.opaque.server_setup = Some(generate_opaque_server_setup_secret());
    AppState {
        opaque_server_setup: Arc::new(opaque_server_setup_from_config(&config).unwrap()),
        config,
        storage,
        pending_logins: Arc::new(Mutex::new(HashMap::new())),
    }
}

async fn test_storage_without_migrations() -> Option<Storage> {
    let Ok(database_url) = std::env::var("UMBRA_TEST_DATABASE_URL") else {
        eprintln!("skipping postgres test: UMBRA_TEST_DATABASE_URL is not set");
        return None;
    };
    Some(Storage::connect(&database_url).await.unwrap())
}

async fn fresh_test_storage() -> Option<Storage> {
    let storage = test_storage_without_migrations().await?;
    sqlx::query("DROP SCHEMA public CASCADE")
        .execute(storage.pool())
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA public")
        .execute(storage.pool())
        .await
        .unwrap();
    umbra_migrations::run(storage.pool()).await.unwrap();
    Some(storage)
}
