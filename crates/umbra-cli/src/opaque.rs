use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use umbra_protocol::{
    DeviceRegisterRequest, OpaqueLoginFinishRequest, OpaqueLoginFinishResponse,
    OpaqueLoginStartRequest, OpaqueLoginStartResponse, OpaqueRegisterFinishRequest,
    OpaqueRegisterStartRequest, OpaqueRegisterStartResponse, PROTOCOL_VERSION, RegisterResponse,
};

use crate::OpaqueCipherSuite;
use crate::error::CliError;
use crate::http::{PublicHttpClient, decode_b64, encode_b64};
use crate::keys::DeviceSigningKey;

pub(crate) struct AccountRegistrationMaterial {
    pub(crate) public_key: String,
    pub(crate) encrypted_private_key: serde_json::Value,
}

pub async fn register(
    client: &PublicHttpClient,
    email: &str,
    display_name: Option<String>,
    password: &[u8],
    device_name: &str,
    device_key: &DeviceSigningKey,
    account_material: AccountRegistrationMaterial,
) -> Result<RegisterResponse, CliError> {
    let registration_start = ClientRegistration::<OpaqueCipherSuite>::start(&mut OsRng, password)
        .map_err(|_| CliError::Opaque("registration start failed"))?;
    let start_response: OpaqueRegisterStartResponse = client
        .post(
            "/api/v1/auth/register/start",
            &OpaqueRegisterStartRequest {
                protocol_version: PROTOCOL_VERSION,
                email: email.to_owned(),
                registration_request: encode_b64(registration_start.message.serialize().as_slice()),
            },
        )
        .await?;
    let registration_response = RegistrationResponse::<OpaqueCipherSuite>::deserialize(
        &decode_b64(&start_response.registration_response)?,
    )
    .map_err(|_| CliError::Opaque("invalid registration response"))?;
    let registration_finish = registration_start
        .state
        .finish(
            &mut OsRng,
            password,
            registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| CliError::Opaque("registration finish failed"))?;

    client
        .post(
            "/api/v1/auth/register/finish",
            &OpaqueRegisterFinishRequest {
                protocol_version: PROTOCOL_VERSION,
                registration_id: start_response.registration_id,
                email: email.to_owned(),
                display_name,
                public_key: account_material.public_key,
                encrypted_private_key: account_material.encrypted_private_key,
                initial_device: DeviceRegisterRequest {
                    name: device_name.to_owned(),
                    public_key: device_key.public_key_base64url(),
                    fingerprint: device_key.fingerprint(),
                },
                registration_upload: encode_b64(registration_finish.message.serialize().as_slice()),
            },
        )
        .await
}

pub async fn login(
    client: &PublicHttpClient,
    email: &str,
    password: &[u8],
    device_id: uuid::Uuid,
) -> Result<OpaqueLoginFinishResponse, CliError> {
    let login_start = ClientLogin::<OpaqueCipherSuite>::start(&mut OsRng, password)
        .map_err(|_| CliError::Opaque("login start failed"))?;
    let start_response: OpaqueLoginStartResponse = client
        .post(
            "/api/v1/auth/login/start",
            &OpaqueLoginStartRequest {
                protocol_version: PROTOCOL_VERSION,
                email: email.to_owned(),
                credential_request: encode_b64(login_start.message.serialize().as_slice()),
            },
        )
        .await?;
    let credential_response = CredentialResponse::<OpaqueCipherSuite>::deserialize(&decode_b64(
        &start_response.credential_response,
    )?)
    .map_err(|_| CliError::Opaque("invalid credential response"))?;
    let login_finish = login_start
        .state
        .finish(
            &mut OsRng,
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| CliError::Opaque("login finish failed"))?;

    client
        .post(
            "/api/v1/auth/login/finish",
            &OpaqueLoginFinishRequest {
                protocol_version: PROTOCOL_VERSION,
                login_id: start_response.login_id,
                device_id: Some(device_id),
                pending_device: None,
                credential_finalization: encode_b64(login_finish.message.serialize().as_slice()),
            },
        )
        .await
}
