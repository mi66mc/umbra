use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use umbra_core::DeviceState;
use uuid::Uuid;

use crate::state::AppState;
use crate::util::token_hash;
use umbra_auth::{
    HEADER_BODY_SHA256, HEADER_DEVICE_ID, HEADER_NONCE, HEADER_SESSION_ID, HEADER_SIGNATURE,
    HEADER_TIMESTAMP, SignedRequestParts, body_sha256_b64, verify_request, verifying_key_from_b64,
};

pub(crate) const AUTHENTICATED_USER_HEADER: &str = "x-umbra-authenticated-user";
pub(crate) const AUTHENTICATED_DEVICE_HEADER: &str = "x-umbra-authenticated-device";
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticatedUser {
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
}

pub(crate) fn authenticated_user_from_headers(headers: &HeaderMap) -> Option<AuthenticatedUser> {
    let user_id = headers
        .get(AUTHENTICATED_USER_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())?;
    let device_id = headers
        .get(AUTHENTICATED_DEVICE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok());

    Some(AuthenticatedUser { user_id, device_id })
}

pub(crate) async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    request.headers_mut().remove(AUTHENTICATED_USER_HEADER);
    request.headers_mut().remove(AUTHENTICATED_DEVICE_HEADER);
    let (mut parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let authenticated =
        if let Some(authenticated) = authenticate_bearer(&state, &parts.headers).await? {
            authenticated
        } else {
            authenticate_signed(&state, &parts, &body_bytes).await?
        };

    let user_header_value = authenticated
        .user_id
        .to_string()
        .parse()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    parts
        .headers
        .insert(AUTHENTICATED_USER_HEADER, user_header_value);
    if let Some(device_id) = authenticated.device_id {
        let device_header_value = device_id
            .to_string()
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        parts
            .headers
            .insert(AUTHENTICATED_DEVICE_HEADER, device_header_value);
    }
    Ok(next
        .run(Request::from_parts(parts, Body::from(body_bytes)))
        .await)
}

async fn authenticate_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AuthenticatedUser>, StatusCode> {
    let Some(token) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Ok(None);
    };

    let session = state
        .storage
        .find_active_session_by_hash(&token_hash(token))
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if session.auth_scheme != "bearer" {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Some(AuthenticatedUser {
        user_id: session.user_id,
        device_id: session.device_id,
    }))
}

async fn authenticate_signed(
    state: &AppState,
    parts: &axum::http::request::Parts,
    body: &[u8],
) -> Result<AuthenticatedUser, StatusCode> {
    let session_id = parse_uuid_header(&parts.headers, HEADER_SESSION_ID)?;
    let device_id = parse_uuid_header(&parts.headers, HEADER_DEVICE_ID)?;
    let timestamp_unix = required_header(&parts.headers, HEADER_TIMESTAMP)?
        .parse::<i64>()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now = Utc::now().timestamp();
    if (now - timestamp_unix).abs() > MAX_CLOCK_SKEW_SECONDS {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let nonce = required_header(&parts.headers, HEADER_NONCE)?.to_owned();
    let body_sha256 = required_header(&parts.headers, HEADER_BODY_SHA256)?.to_owned();
    if body_sha256 != body_sha256_b64(body) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let signature = required_header(&parts.headers, HEADER_SIGNATURE)?;
    let session = state
        .storage
        .find_active_session_by_id(session_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if session.auth_scheme != "signed" || session.device_id != Some(device_id) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device = state
        .storage
        .find_device_by_id(device_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if device.user_id != session.user_id
        || device.state != DeviceState::Trusted
        || device.revoked_at.is_some()
        || device.public_key.is_none()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let verifying_key =
        verifying_key_from_b64(device.public_key.as_deref().unwrap()).map_err(|_| {
            tracing::warn!("stored device public key is not a valid ed25519 key");
            StatusCode::UNAUTHORIZED
        })?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| parts.uri.path().to_owned());
    let signed_parts = SignedRequestParts {
        method: parts.method.as_str().to_owned(),
        path_and_query,
        body_sha256,
        timestamp_unix,
        nonce: nonce.clone(),
        session_id,
        device_id,
    };
    verify_request(&verifying_key, &signed_parts, signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .storage
        .remember_session_nonce(session_id, &nonce)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(AuthenticatedUser {
        user_id: session.user_id,
        device_id: Some(device_id),
    })
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, StatusCode> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn parse_uuid_header(headers: &HeaderMap, name: &str) -> Result<Uuid, StatusCode> {
    Uuid::parse_str(required_header(headers, name)?).map_err(|_| StatusCode::UNAUTHORIZED)
}
