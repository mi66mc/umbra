use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use umbra_auth::{signing_key_from_b64, signing_key_to_b64, verifying_key_to_b64};

use crate::error::CliError;

#[derive(Clone)]
pub struct DeviceSigningKey {
    signing_key: SigningKey,
}

impl DeviceSigningKey {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_base64url(value: &str) -> Result<Self, CliError> {
        Ok(Self {
            signing_key: signing_key_from_b64(value)?,
        })
    }

    pub fn to_base64url(&self) -> String {
        signing_key_to_b64(&self.signing_key)
    }

    pub fn public_key_base64url(&self) -> String {
        verifying_key_to_b64(&self.signing_key.verifying_key())
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.signing_key.verifying_key().as_bytes());
        format!("SHA256:{}", Base64UrlUnpadded::encode_string(&digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_device_key_roundtrips() {
        let key = DeviceSigningKey::generate();
        let encoded = key.to_base64url();
        let decoded = DeviceSigningKey::from_base64url(&encoded).unwrap();

        assert_eq!(decoded.public_key_base64url(), key.public_key_base64url());
        assert!(key.fingerprint().starts_with("SHA256:"));
    }
}
