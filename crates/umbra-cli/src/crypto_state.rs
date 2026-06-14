#![allow(dead_code)]

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
}
