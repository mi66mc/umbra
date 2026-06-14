use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SIGNATURE_SCHEME: &str = "UMBRA-SIGNED-REQUEST-V1";
pub const HEADER_SESSION_ID: &str = "umbra-session-id";
pub const HEADER_DEVICE_ID: &str = "umbra-device-id";
pub const HEADER_TIMESTAMP: &str = "umbra-timestamp";
pub const HEADER_NONCE: &str = "umbra-nonce";
pub const HEADER_BODY_SHA256: &str = "umbra-body-sha256";
pub const HEADER_SIGNATURE: &str = "umbra-signature";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequestParts {
    pub method: String,
    pub path_and_query: String,
    pub body_sha256: String,
    pub timestamp_unix: i64,
    pub nonce: String,
    pub session_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("invalid signing key")]
    InvalidSigningKey,
    #[error("invalid verifying key")]
    InvalidVerifyingKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid encoding")]
    InvalidEncoding,
}

pub fn body_sha256_b64(body: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(body))
}

pub fn canonical_request(parts: &SignedRequestParts) -> String {
    [
        SIGNATURE_SCHEME.to_owned(),
        parts.method.to_uppercase(),
        parts.path_and_query.clone(),
        parts.body_sha256.clone(),
        parts.timestamp_unix.to_string(),
        parts.nonce.clone(),
        parts.session_id.to_string(),
        parts.device_id.to_string(),
    ]
    .join("\n")
}

pub fn sign_request(signing_key: &SigningKey, parts: &SignedRequestParts) -> String {
    let signature = signing_key.sign(canonical_request(parts).as_bytes());
    Base64UrlUnpadded::encode_string(&signature.to_bytes())
}

pub fn verify_request(
    verifying_key: &VerifyingKey,
    parts: &SignedRequestParts,
    signature_b64: &str,
) -> Result<(), AuthError> {
    let bytes =
        Base64UrlUnpadded::decode_vec(signature_b64).map_err(|_| AuthError::InvalidEncoding)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| AuthError::InvalidSignature)?;
    verifying_key
        .verify(canonical_request(parts).as_bytes(), &signature)
        .map_err(|_| AuthError::InvalidSignature)
}

pub fn signing_key_to_b64(signing_key: &SigningKey) -> String {
    Base64UrlUnpadded::encode_string(&signing_key.to_bytes())
}

pub fn verifying_key_to_b64(verifying_key: &VerifyingKey) -> String {
    Base64UrlUnpadded::encode_string(verifying_key.as_bytes())
}

pub fn signing_key_from_b64(value: &str) -> Result<SigningKey, AuthError> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| AuthError::InvalidEncoding)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidSigningKey)?;
    Ok(SigningKey::from_bytes(&array))
}

pub fn verifying_key_from_b64(value: &str) -> Result<VerifyingKey, AuthError> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| AuthError::InvalidEncoding)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidVerifyingKey)?;
    VerifyingKey::from_bytes(&array).map_err(|_| AuthError::InvalidVerifyingKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use uuid::Uuid;

    #[test]
    fn body_hash_is_base64url_sha256() {
        let hash = body_sha256_b64(br#"{"hello":"world"}"#);

        assert_eq!(hash, "k6I5cakU5erL8KjSUVTNownDwccvu5kU1Hxg88toFYg");
    }

    #[test]
    fn canonical_request_is_stable() {
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let parts = SignedRequestParts {
            method: "POST".to_owned(),
            path_and_query: "/api/v1/sync?x=1".to_owned(),
            body_sha256: "bodyhash".to_owned(),
            timestamp_unix: 1_700_000_000,
            nonce: "nonce-1".to_owned(),
            session_id,
            device_id,
        };

        assert_eq!(
            canonical_request(&parts),
            "UMBRA-SIGNED-REQUEST-V1\nPOST\n/api/v1/sync?x=1\nbodyhash\n1700000000\nnonce-1\n00000000-0000-0000-0000-000000000001\n00000000-0000-0000-0000-000000000002"
        );
    }

    #[test]
    fn signed_request_verifies_and_tampering_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let parts = SignedRequestParts {
            method: "GET".to_owned(),
            path_and_query: "/api/v1/vaults".to_owned(),
            body_sha256: body_sha256_b64(b""),
            timestamp_unix: 1_700_000_000,
            nonce: "nonce-2".to_owned(),
            session_id,
            device_id,
        };

        let signature = sign_request(&signing_key, &parts);

        verify_request(&verifying_key, &parts, &signature).unwrap();

        let mut tampered = parts.clone();
        tampered.path_and_query = "/api/v1/orgs".to_owned();
        assert_eq!(
            verify_request(&verifying_key, &tampered, &signature),
            Err(AuthError::InvalidSignature)
        );
    }
}
