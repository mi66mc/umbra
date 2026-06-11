use serde::{Deserialize, Serialize};

pub const ENVELOPE_VERSION_V1: u16 = 1;
pub const DEFAULT_SUITE: &str = "UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KdfProfile {
    Interactive,
    Balanced,
    Hardened,
    Paranoid,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idParams {
    pub profile: KdfProfile,
    pub memory_mib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

impl Argon2idParams {
    pub fn balanced_with_salt(salt: impl Into<String>) -> Self {
        Self {
            profile: KdfProfile::Balanced,
            memory_mib: 128,
            iterations: 4,
            parallelism: 1,
            salt: salt.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AadV1 {
    pub app: String,
    pub purpose: String,
    pub schema: u16,
    pub vault_id: String,
    pub item_id: Option<String>,
    pub revision: Option<i64>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoEnvelopeV1 {
    pub version: u16,
    pub suite: String,
    pub nonce: String,
    pub aad: AadV1,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyWrappingEnvelopeV1 {
    pub version: u16,
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub wrapping: VaultKeyWrappingV1,
    pub encryption: EncryptionPayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyWrappingV1 {
    pub method: String,
    pub recipient_public_key: Option<String>,
    pub kdf: Option<Argon2idParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionPayloadV1 {
    pub alg: String,
    pub nonce: String,
    pub aad: AadV1,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported envelope version {0}")]
    UnsupportedEnvelopeVersion(u16),
}

pub fn assert_supported_envelope_version(version: u16) -> Result<(), CryptoError> {
    if version == ENVELOPE_VERSION_V1 {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedEnvelopeVersion(version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_params_are_serializable() {
        let params = Argon2idParams::balanced_with_salt("salt");
        let json = serde_json::to_string(&params).unwrap();
        let decoded: Argon2idParams = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, params);
    }
}
