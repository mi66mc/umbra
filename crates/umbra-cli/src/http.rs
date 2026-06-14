use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use reqwest::{Client, Method};
use serde::{Serialize, de::DeserializeOwned};
use umbra_auth::{
    HEADER_BODY_SHA256, HEADER_DEVICE_ID, HEADER_NONCE, HEADER_SESSION_ID, HEADER_SIGNATURE,
    HEADER_TIMESTAMP, SignedRequestParts, body_sha256_b64, sign_request,
};

use crate::config::ProfileConfig;
use crate::error::CliError;
use crate::keys::DeviceSigningKey;

#[derive(Clone)]
pub struct PublicHttpClient {
    base_url: String,
    inner: Client,
}

impl PublicHttpClient {
    pub fn new(server_url: &str) -> Result<Self, CliError> {
        Ok(Self {
            base_url: server_url.trim_end_matches('/').to_owned(),
            inner: http_client()?,
        })
    }

    pub async fn post<T, R>(&self, path: &str, body: &T) -> Result<R, CliError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let body_bytes = serde_json::to_vec(body)?;
        send_json(
            self.inner
                .request(Method::POST, format!("{}{}", self.base_url, path))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes),
        )
        .await
    }
}

#[derive(Clone)]
pub struct UmbraHttpClient {
    base_url: String,
    session_id: Option<uuid::Uuid>,
    device_id: Option<uuid::Uuid>,
    device_key: Option<DeviceSigningKey>,
    legacy_token: Option<String>,
    inner: Client,
}

impl UmbraHttpClient {
    pub fn new(profile: &ProfileConfig) -> Result<Self, CliError> {
        Ok(Self {
            base_url: profile.server_url.trim_end_matches('/').to_owned(),
            session_id: profile.session_id,
            device_id: profile.device_id,
            device_key: profile
                .device_private_key
                .as_deref()
                .map(DeviceSigningKey::from_base64url)
                .transpose()?,
            legacy_token: profile.legacy_session_token.clone(),
            inner: http_client()?,
        })
    }

    pub async fn get<R>(&self, path: &str) -> Result<R, CliError>
    where
        R: DeserializeOwned,
    {
        self.send(Method::GET, path, Vec::new()).await
    }

    pub async fn post<T, R>(&self, path: &str, body: &T) -> Result<R, CliError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        self.send(Method::POST, path, serde_json::to_vec(body)?)
            .await
    }

    pub async fn put<T, R>(&self, path: &str, body: &T) -> Result<R, CliError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        self.send(Method::PUT, path, serde_json::to_vec(body)?)
            .await
    }

    async fn send<R>(&self, method: Method, path: &str, body: Vec<u8>) -> Result<R, CliError>
    where
        R: DeserializeOwned,
    {
        let mut request = self
            .inner
            .request(method.clone(), format!("{}{}", self.base_url, path));
        if !body.is_empty() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.clone());
        }

        if let (Some(session_id), Some(device_id), Some(device_key)) =
            (self.session_id, self.device_id, self.device_key.as_ref())
        {
            let nonce = uuid::Uuid::new_v4().to_string();
            let body_hash = body_sha256_b64(&body);
            let timestamp_unix = chrono::Utc::now().timestamp();
            let parts = SignedRequestParts {
                method: method.as_str().to_owned(),
                path_and_query: path.to_owned(),
                body_sha256: body_hash.clone(),
                timestamp_unix,
                nonce: nonce.clone(),
                session_id,
                device_id,
            };
            let signature = sign_request(device_key.signing_key(), &parts);
            request = request
                .header(HEADER_SESSION_ID, session_id.to_string())
                .header(HEADER_DEVICE_ID, device_id.to_string())
                .header(HEADER_TIMESTAMP, timestamp_unix.to_string())
                .header(HEADER_NONCE, nonce)
                .header(HEADER_BODY_SHA256, body_hash)
                .header(HEADER_SIGNATURE, signature);
        } else if let Some(token) = &self.legacy_token {
            request = request.bearer_auth(token);
        } else {
            return Err(CliError::NotLoggedIn);
        }

        send_json(request).await
    }
}

pub fn encode_b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub fn decode_b64(value: &str) -> Result<Vec<u8>, CliError> {
    Base64UrlUnpadded::decode_vec(value).map_err(|_| CliError::InvalidEncoding)
}

fn http_client() -> Result<Client, CliError> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}

async fn send_json<R>(request: reqwest::RequestBuilder) -> Result<R, CliError>
where
    R: DeserializeOwned,
{
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(CliError::ServerStatus { status, body });
    }

    Ok(serde_json::from_str(&body)?)
}
