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
use umbra_core::VaultKind;
use umbra_protocol::{
    CreateOrgRequest, CreateVaultRequest, DeviceRegisterRequest, OpaqueLoginFinishRequest,
    OpaqueLoginFinishResponse, OpaqueLoginStartRequest, OpaqueLoginStartResponse,
    OpaqueRegisterFinishRequest, OpaqueRegisterStartRequest, OpaqueRegisterStartResponse,
    OrgResponse, PROTOCOL_VERSION, RegisterResponse, VaultResponse,
};
use umbra_storage::Storage;

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
            name: "Personal".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(vault.org_id, None);
    assert_eq!(vault.current_key_generation, 1);
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
            credential_finalization: encode_b64(login_finish.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    finish.session_token
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
    (status, serde_json::from_slice(&body).unwrap())
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
