#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use umbra_crypto::{
    AadV1, Argon2idParams, CryptoEnvelopeV1, MasterPassword, Salt, UserKeypair, UserPrivateKey,
    UserPublicKey, UserSecretKey, decrypt_user_private_key, derive_account_kek,
    encrypt_user_private_key, generate_user_keypair,
};

use crate::config::ProfileConfig;
use crate::error::CliError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewAccountCrypto {
    pub(crate) public_key: UserPublicKey,
    pub(crate) user_secret_key: UserSecretKey,
    pub(crate) kdf_params: Argon2idParams,
    pub(crate) encrypted_private_key: CryptoEnvelopeV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnlockedAccountCrypto {
    pub(crate) public_key: UserPublicKey,
    pub(crate) private_key: UserPrivateKey,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EmergencyKitV1 {
    pub(crate) version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<String>,
    pub(crate) account_public_key: String,
    pub(crate) user_secret_key: String,
    pub(crate) kdf_params: Argon2idParams,
}

impl std::fmt::Debug for EmergencyKitV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmergencyKitV1")
            .field("version", &self.version)
            .field("email", &self.email)
            .field("account_public_key", &self.account_public_key)
            .field("user_secret_key", &"[redacted]")
            .field("kdf_params", &self.kdf_params)
            .finish()
    }
}

impl EmergencyKitV1 {
    pub(crate) fn from_account_crypto(
        email: Option<String>,
        account_crypto: &NewAccountCrypto,
    ) -> Self {
        Self {
            version: 1,
            email,
            account_public_key: account_crypto.public_key.to_base64url(),
            user_secret_key: account_crypto.user_secret_key.to_base64url(),
            kdf_params: account_crypto.kdf_params.clone(),
        }
    }

    pub(crate) fn from_profile(profile: &ProfileConfig) -> Result<Self, CliError> {
        let account_public_key = profile
            .client_public_key
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?;
        let user_secret_key = profile
            .user_secret_key
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?;
        let kdf_params = profile
            .kdf_params
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?;

        Ok(Self {
            version: 1,
            email: profile.email.clone(),
            account_public_key,
            user_secret_key,
            kdf_params,
        })
    }
}

impl NewAccountCrypto {
    pub(crate) fn generate(password: &MasterPassword) -> Result<Self, CliError> {
        let user_secret_key = UserSecretKey::generate();
        let keypair = generate_user_keypair();
        let public_key = keypair.public_key;
        let kdf_params = Argon2idParams::balanced_with_salt(Salt::generate().to_base64url());
        let account_kek = derive_account_kek(password, &user_secret_key, &kdf_params)?;
        let encrypted_private_key = encrypt_user_private_key(
            &account_kek,
            &keypair.private_key,
            AadV1::user_private_key(public_key.to_base64url()),
        )?;

        Ok(Self {
            public_key,
            user_secret_key,
            kdf_params,
            encrypted_private_key,
        })
    }

    pub(crate) fn unlock(
        &self,
        password: &MasterPassword,
    ) -> Result<UnlockedAccountCrypto, CliError> {
        let account_kek = derive_account_kek(password, &self.user_secret_key, &self.kdf_params)?;
        let private_key = decrypt_user_private_key(
            &account_kek,
            &AadV1::user_private_key(self.public_key.to_base64url()),
            &self.encrypted_private_key,
        )?;

        Ok(UnlockedAccountCrypto {
            public_key: self.public_key,
            private_key,
        })
    }
}

pub(crate) fn load_unlocked_profile(
    profile: &ProfileConfig,
    password: &MasterPassword,
) -> Result<UnlockedAccountCrypto, CliError> {
    let public_key = profile
        .client_public_key
        .as_deref()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| UserPublicKey::from_base64url(value).map_err(CliError::from))?;
    let user_secret_key = profile
        .user_secret_key
        .as_deref()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| UserSecretKey::from_base64url(value).map_err(CliError::from))?;
    let kdf_params = profile
        .kdf_params
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)?;
    let encrypted_private_key = profile
        .encrypted_user_private_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| serde_json::from_value(value).map_err(CliError::from))?;

    let account_crypto = NewAccountCrypto {
        public_key,
        user_secret_key,
        kdf_params,
        encrypted_private_key,
    };
    account_crypto.unlock(password)
}

pub(crate) fn unlock_profile_with_emergency_kit(
    profile: &ProfileConfig,
    password: &MasterPassword,
    emergency_kit: &EmergencyKitV1,
) -> Result<UnlockedAccountCrypto, CliError> {
    if emergency_kit.version != 1 {
        return Err(CliError::Input("unsupported emergency kit version"));
    }

    let public_key = UserPublicKey::from_base64url(&emergency_kit.account_public_key)?;
    let user_secret_key = UserSecretKey::from_base64url(&emergency_kit.user_secret_key)?;
    let encrypted_private_key = profile
        .encrypted_user_private_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| serde_json::from_value(value).map_err(CliError::from))?;

    let account_crypto = NewAccountCrypto {
        public_key,
        user_secret_key,
        kdf_params: emergency_kit.kdf_params.clone(),
        encrypted_private_key,
    };

    account_crypto.unlock(password)
}

pub(crate) fn keypair_from_unlocked(unlocked: &UnlockedAccountCrypto) -> UserKeypair {
    UserKeypair {
        public_key: unlocked.public_key,
        private_key: unlocked.private_key.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_crypto::MasterPassword;

    #[test]
    fn generated_account_crypto_unlocks_private_key() {
        let password = MasterPassword::new("correct horse battery staple");
        let account_crypto = NewAccountCrypto::generate(&password).unwrap();

        let unlocked = account_crypto.unlock(&password).unwrap();

        assert_eq!(unlocked.public_key, account_crypto.public_key);
        assert_eq!(
            unlocked.private_key.to_base64url(),
            keypair_from_unlocked(&unlocked).private_key.to_base64url()
        );
    }

    #[test]
    fn generated_account_crypto_rejects_wrong_password() {
        let password = MasterPassword::new("correct horse battery staple");
        let wrong_password = MasterPassword::new("wrong horse battery staple");
        let account_crypto = NewAccountCrypto::generate(&password).unwrap();

        assert!(account_crypto.unlock(&wrong_password).is_err());
    }

    #[test]
    fn emergency_kit_roundtrips_without_private_key_material() {
        let password = MasterPassword::new("correct horse battery staple");
        let account_crypto = NewAccountCrypto::generate(&password).unwrap();

        let kit = EmergencyKitV1::from_account_crypto(
            Some("miguel@example.com".to_owned()),
            &account_crypto,
        );
        let encoded = serde_json::to_string_pretty(&kit).unwrap();

        assert!(encoded.contains("\"version\": 1"));
        assert!(encoded.contains("miguel@example.com"));
        assert!(encoded.contains(&account_crypto.public_key.to_base64url()));
        assert!(encoded.contains(&account_crypto.user_secret_key.to_base64url()));
        assert!(!encoded.contains("encrypted_private_key"));
        assert!(!encoded.contains("private_key"));

        let decoded: EmergencyKitV1 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, kit);
    }

    #[test]
    fn emergency_kit_debug_redacts_user_secret_key() {
        let password = MasterPassword::new("correct horse battery staple");
        let account_crypto = NewAccountCrypto::generate(&password).unwrap();
        let kit = EmergencyKitV1::from_account_crypto(None, &account_crypto);

        let debug = format!("{kit:?}");

        assert!(!debug.contains(&account_crypto.user_secret_key.to_base64url()));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn unlock_profile_with_emergency_kit_works_without_profile_secret_key() {
        let password = MasterPassword::new("correct horse battery staple");
        let account_crypto = NewAccountCrypto::generate(&password).unwrap();
        let kit = EmergencyKitV1::from_account_crypto(None, &account_crypto);
        let clean_profile = ProfileConfig {
            encrypted_user_private_key: Some(
                serde_json::to_value(account_crypto.encrypted_private_key.clone()).unwrap(),
            ),
            user_secret_key: None,
            kdf_params: None,
            client_public_key: None,
            ..ProfileConfig::default()
        };

        let unlocked = unlock_profile_with_emergency_kit(&clean_profile, &password, &kit).unwrap();

        assert_eq!(unlocked.public_key, account_crypto.public_key);
        assert_eq!(
            unlocked.private_key.to_base64url(),
            account_crypto
                .unlock(&password)
                .unwrap()
                .private_key
                .to_base64url()
        );
    }

    #[test]
    fn unlock_profile_with_emergency_kit_rejects_wrong_password() {
        let password = MasterPassword::new("correct horse battery staple");
        let wrong_password = MasterPassword::new("wrong horse battery staple");
        let account_crypto = NewAccountCrypto::generate(&password).unwrap();
        let kit = EmergencyKitV1::from_account_crypto(None, &account_crypto);
        let clean_profile = ProfileConfig {
            encrypted_user_private_key: Some(
                serde_json::to_value(account_crypto.encrypted_private_key.clone()).unwrap(),
            ),
            ..ProfileConfig::default()
        };

        assert!(unlock_profile_with_emergency_kit(&clean_profile, &wrong_password, &kit).is_err());
    }
}
