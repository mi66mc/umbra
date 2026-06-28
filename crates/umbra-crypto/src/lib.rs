use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ENVELOPE_VERSION_V1: u16 = 1;
pub const DEFAULT_SUITE: &str = "UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1";
pub const XCHACHA20_POLY1305_ALG: &str = "xchacha20-poly1305";
pub const VAULT_KEY_WRAPPING_TYPE: &str = "vault_key_wrapping";
pub const USER_PUBLIC_KEY_WRAPPING_METHOD: &str = "user_public_key";
pub const DEVICE_BOOTSTRAP_TYPE: &str = "device_bootstrap";
pub const DEVICE_RECOVERY_CHALLENGE_TYPE: &str = "device_recovery_challenge";
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MasterPassword(Vec<u8>);

impl MasterPassword {
    pub fn new(password: impl Into<Vec<u8>>) -> Self {
        Self(password.into())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterPassword([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct UserSecretKey([u8; KEY_LEN]);

impl UserSecretKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }

    pub fn from_base64url(encoded: &str) -> Result<Self, CryptoError> {
        Ok(Self(decode_array(encoded)?))
    }
}

impl std::fmt::Debug for UserSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserSecretKey([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AccountKek([u8; KEY_LEN]);

impl AccountKek {
    fn as_key(&self) -> &Key {
        Key::from_slice(&self.0)
    }
}

impl std::fmt::Debug for AccountKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKek([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalUnlockKey([u8; KEY_LEN]);

impl LocalUnlockKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    fn as_key(&self) -> &Key {
        Key::from_slice(&self.0)
    }

    pub fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }

    pub fn from_base64url(encoded: &str) -> Result<Self, CryptoError> {
        Ok(Self(decode_array(encoded)?))
    }
}

impl std::fmt::Debug for LocalUnlockKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalUnlockKey([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct UserPrivateKey([u8; KEY_LEN]);

impl UserPrivateKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes_array(&self) -> Result<[u8; KEY_LEN], CryptoError> {
        Ok(self.0)
    }

    fn static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.0)
    }

    pub fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }

    pub fn from_base64url(encoded: &str) -> Result<Self, CryptoError> {
        Ok(Self(decode_array(encoded)?))
    }
}

impl std::fmt::Debug for UserPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserPrivateKey([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublicKey([u8; KEY_LEN]);

impl UserPublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes_array(&self) -> Result<[u8; KEY_LEN], CryptoError> {
        Ok(self.0)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.0)
    }

    pub fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }

    pub fn from_base64url(encoded: &str) -> Result<Self, CryptoError> {
        Ok(Self(decode_array(encoded)?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserKeypair {
    pub public_key: UserPublicKey,
    pub private_key: UserPrivateKey,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }

    pub fn from_base64url(encoded: &str) -> Result<Self, CryptoError> {
        Ok(Self(decode_array(encoded)?))
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ItemKey([u8; KEY_LEN]);

impl ItemKey {
    fn as_key(&self) -> &Key {
        Key::from_slice(&self.0)
    }
}

impl std::fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemKey([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Salt([u8; 16]);

impl Salt {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Salt([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    fn generate() -> Self {
        let mut bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn as_xnonce(&self) -> &XNonce {
        XNonce::from_slice(&self.0)
    }

    fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Nonce([redacted])")
    }
}

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
    pub fn interactive_with_salt(salt: impl Into<String>) -> Self {
        Self {
            profile: KdfProfile::Interactive,
            memory_mib: 64,
            iterations: 3,
            parallelism: 1,
            salt: salt.into(),
        }
    }

    pub fn balanced_with_salt(salt: impl Into<String>) -> Self {
        Self {
            profile: KdfProfile::Balanced,
            memory_mib: 128,
            iterations: 4,
            parallelism: 1,
            salt: salt.into(),
        }
    }

    pub fn hardened_with_salt(salt: impl Into<String>) -> Self {
        Self {
            profile: KdfProfile::Hardened,
            memory_mib: 256,
            iterations: 5,
            parallelism: 2,
            salt: salt.into(),
        }
    }

    pub fn paranoid_with_salt(salt: impl Into<String>) -> Self {
        Self {
            profile: KdfProfile::Paranoid,
            memory_mib: 512,
            iterations: 6,
            parallelism: 2,
            salt: salt.into(),
        }
    }

    fn validate(&self) -> Result<(), CryptoError> {
        if self.memory_mib < 64 || self.iterations < 3 || self.parallelism == 0 {
            return Err(CryptoError::InvalidKdfParams);
        }
        Ok(())
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

impl AadV1 {
    pub fn item(
        vault_id: impl Into<String>,
        item_id: impl Into<String>,
        revision: i64,
        kind: impl Into<String>,
    ) -> Self {
        Self {
            app: "umbra".to_owned(),
            purpose: "item".to_owned(),
            schema: 1,
            vault_id: vault_id.into(),
            item_id: Some(item_id.into()),
            revision: Some(revision),
            kind: Some(kind.into()),
        }
    }

    pub fn vault_key_wrapping(vault_id: impl Into<String>) -> Self {
        Self {
            app: "umbra".to_owned(),
            purpose: VAULT_KEY_WRAPPING_TYPE.to_owned(),
            schema: 1,
            vault_id: vault_id.into(),
            item_id: None,
            revision: None,
            kind: None,
        }
    }

    pub fn user_private_key(user_id: impl Into<String>) -> Self {
        Self {
            app: "umbra".to_owned(),
            purpose: "user_private_key".to_owned(),
            schema: 1,
            vault_id: user_id.into(),
            item_id: None,
            revision: None,
            kind: None,
        }
    }

    pub fn local_unlock_state(profile: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            app: "umbra".to_owned(),
            purpose: "local_unlock_state".to_owned(),
            schema: 1,
            vault_id: profile.into(),
            item_id: Some(device_id.into()),
            revision: None,
            kind: None,
        }
    }

    pub fn device_bootstrap(device_id: impl Into<String>) -> Self {
        Self {
            app: "umbra".to_owned(),
            purpose: DEVICE_BOOTSTRAP_TYPE.to_owned(),
            schema: 1,
            vault_id: device_id.into(),
            item_id: None,
            revision: None,
            kind: None,
        }
    }

    pub fn recovery_challenge(
        device_id: impl Into<String>,
        challenge_id: impl Into<String>,
    ) -> Self {
        Self {
            app: "umbra".to_owned(),
            purpose: DEVICE_RECOVERY_CHALLENGE_TYPE.to_owned(),
            schema: 1,
            vault_id: device_id.into(),
            item_id: Some(challenge_id.into()),
            revision: None,
            kind: None,
        }
    }
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
    pub ephemeral_public_key: Option<String>,
    pub kdf: Option<Argon2idParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionPayloadV1 {
    pub alg: String,
    pub nonce: String,
    pub aad: AadV1,
    pub ciphertext: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBootstrapBundleV1 {
    pub version: u16,
    pub user_secret_key: String,
    pub kdf_params: Argon2idParams,
    pub encrypted_user_private_key: CryptoEnvelopeV1,
    pub account_public_key: String,
    pub default_vault_id: Option<String>,
}

impl std::fmt::Debug for DeviceBootstrapBundleV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceBootstrapBundleV1")
            .field("version", &self.version)
            .field("user_secret_key", &"[redacted]")
            .field("kdf_params", &self.kdf_params)
            .field(
                "encrypted_user_private_key",
                &self.encrypted_user_private_key,
            )
            .field("account_public_key", &self.account_public_key)
            .field("default_vault_id", &self.default_vault_id)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBootstrapEnvelopeV1 {
    pub version: u16,
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub recipient_public_key: String,
    pub ephemeral_public_key: String,
    pub encryption: EncryptionPayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallengeEnvelopeV1 {
    pub version: u16,
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub recipient_public_key: String,
    pub ephemeral_public_key: String,
    pub encryption: EncryptionPayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported envelope version {0}")]
    UnsupportedEnvelopeVersion(u16),
    #[error("invalid kdf params")]
    InvalidKdfParams,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("aad mismatch")]
    AadMismatch,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("missing envelope field {0}")]
    MissingEnvelopeField(&'static str),
}

pub fn assert_supported_envelope_version(version: u16) -> Result<(), CryptoError> {
    if version == ENVELOPE_VERSION_V1 {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedEnvelopeVersion(version))
    }
}

pub fn generate_user_keypair() -> UserKeypair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    UserKeypair {
        public_key: UserPublicKey(public.to_bytes()),
        private_key: UserPrivateKey(private.to_bytes()),
    }
}

pub fn derive_account_kek(
    password: &MasterPassword,
    secret_key: &UserSecretKey,
    params: &Argon2idParams,
) -> Result<AccountKek, CryptoError> {
    params.validate()?;

    let salt = decode_b64(&params.salt)?;
    let memory_kib = params
        .memory_mib
        .checked_mul(1024)
        .ok_or(CryptoError::InvalidKdfParams)?;
    let argon_params = Params::new(
        memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::InvalidKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut input = Vec::with_capacity(password.as_bytes().len() + KEY_LEN);
    input.extend_from_slice(password.as_bytes());
    input.extend_from_slice(secret_key.as_bytes());

    let mut output = [0u8; KEY_LEN];
    argon2
        .hash_password_into(&input, &salt, &mut output)
        .map_err(|_| CryptoError::InvalidKdfParams)?;
    input.zeroize();

    Ok(AccountKek(output))
}

pub fn encrypt_user_private_key(
    account_kek: &AccountKek,
    private_key: &UserPrivateKey,
    aad: AadV1,
) -> Result<CryptoEnvelopeV1, CryptoError> {
    encrypt_with_key(account_kek.as_key(), aad, &private_key.0)
}

pub fn decrypt_user_private_key(
    account_kek: &AccountKek,
    expected_aad: &AadV1,
    envelope: &CryptoEnvelopeV1,
) -> Result<UserPrivateKey, CryptoError> {
    let plaintext = decrypt_with_key(account_kek.as_key(), expected_aad, envelope)?;
    Ok(UserPrivateKey(bytes_to_array(&plaintext)?))
}

pub fn encrypt_local_unlock_state(
    key: &LocalUnlockKey,
    aad: AadV1,
    plaintext: &[u8],
) -> Result<CryptoEnvelopeV1, CryptoError> {
    encrypt_with_key(key.as_key(), aad, plaintext)
}

pub fn decrypt_local_unlock_state(
    key: &LocalUnlockKey,
    expected_aad: &AadV1,
    envelope: &CryptoEnvelopeV1,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_with_key(key.as_key(), expected_aad, envelope)
}

pub fn generate_vault_key() -> VaultKey {
    VaultKey::generate()
}

pub fn wrap_vault_key_for_user(
    public_key: &UserPublicKey,
    vault_key: &VaultKey,
    aad: AadV1,
) -> Result<VaultKeyWrappingEnvelopeV1, CryptoError> {
    let ephemeral_private = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_private);
    let shared_secret = ephemeral_private.diffie_hellman(&public_key.public_key());
    ensure_contributory_shared_secret(shared_secret.as_bytes())?;
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), &aad)?;
    let envelope = encrypt_with_key(
        Key::from_slice(&wrapping_key),
        aad.clone(),
        vault_key.as_bytes(),
    )?;

    Ok(VaultKeyWrappingEnvelopeV1 {
        version: ENVELOPE_VERSION_V1,
        envelope_type: VAULT_KEY_WRAPPING_TYPE.to_owned(),
        wrapping: VaultKeyWrappingV1 {
            method: USER_PUBLIC_KEY_WRAPPING_METHOD.to_owned(),
            recipient_public_key: Some(public_key.to_base64url()),
            ephemeral_public_key: Some(encode_b64(&ephemeral_public.to_bytes())),
            kdf: None,
        },
        encryption: EncryptionPayloadV1 {
            alg: XCHACHA20_POLY1305_ALG.to_owned(),
            nonce: envelope.nonce,
            aad: envelope.aad,
            ciphertext: envelope.ciphertext,
        },
    })
}

pub fn encrypt_device_bootstrap_bundle(
    recipient_public_key: &UserPublicKey,
    aad: AadV1,
    bundle: &DeviceBootstrapBundleV1,
) -> Result<DeviceBootstrapEnvelopeV1, CryptoError> {
    ensure_device_bootstrap_aad(&aad)?;

    let ephemeral_private = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_private);
    let recipient = PublicKey::from(recipient_public_key.as_bytes_array()?);
    let shared_secret = ephemeral_private.diffie_hellman(&recipient);
    ensure_contributory_shared_secret(shared_secret.as_bytes())?;
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), &aad)?;
    let mut plaintext = serde_json::to_vec(bundle).map_err(|_| CryptoError::InvalidEncoding)?;
    let payload_result = encrypt_payload_with_key(Key::from_slice(&wrapping_key), aad, &plaintext);
    plaintext.zeroize();
    let payload = payload_result?;

    Ok(DeviceBootstrapEnvelopeV1 {
        version: ENVELOPE_VERSION_V1,
        envelope_type: DEVICE_BOOTSTRAP_TYPE.to_owned(),
        recipient_public_key: recipient_public_key.to_base64url(),
        ephemeral_public_key: encode_b64(&ephemeral_public.to_bytes()),
        encryption: payload,
    })
}

pub fn decrypt_device_bootstrap_bundle(
    recipient_private_key: &UserPrivateKey,
    expected_aad: &AadV1,
    envelope: &DeviceBootstrapEnvelopeV1,
) -> Result<DeviceBootstrapBundleV1, CryptoError> {
    ensure_device_bootstrap_aad(expected_aad)?;
    assert_supported_envelope_version(envelope.version)?;
    if envelope.envelope_type != DEVICE_BOOTSTRAP_TYPE {
        return Err(CryptoError::MissingEnvelopeField("type"));
    }
    ensure_aad(expected_aad, &envelope.encryption.aad)?;
    ensure_recipient_public_key(recipient_private_key, &envelope.recipient_public_key)?;

    let ephemeral_public =
        PublicKey::from(decode_array::<KEY_LEN>(&envelope.ephemeral_public_key)?);
    let shared_secret = recipient_private_key
        .static_secret()
        .diffie_hellman(&ephemeral_public);
    ensure_contributory_shared_secret(shared_secret.as_bytes())?;
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), expected_aad)?;
    let mut plaintext = decrypt_payload_with_key(
        Key::from_slice(&wrapping_key),
        expected_aad,
        &envelope.encryption,
    )?;
    let bundle = serde_json::from_slice(&plaintext).map_err(|_| CryptoError::InvalidEncoding);
    plaintext.zeroize();

    bundle
}

pub fn encrypt_recovery_challenge(
    recipient_public_key: &UserPublicKey,
    aad: AadV1,
    challenge: &[u8],
) -> Result<RecoveryChallengeEnvelopeV1, CryptoError> {
    ensure_recovery_challenge_aad(&aad)?;

    let ephemeral_private = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_private);
    let recipient = PublicKey::from(recipient_public_key.as_bytes_array()?);
    let shared_secret = ephemeral_private.diffie_hellman(&recipient);
    ensure_contributory_shared_secret(shared_secret.as_bytes())?;
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), &aad)?;
    let payload = encrypt_payload_with_key(Key::from_slice(&wrapping_key), aad, challenge)?;

    Ok(RecoveryChallengeEnvelopeV1 {
        version: ENVELOPE_VERSION_V1,
        envelope_type: DEVICE_RECOVERY_CHALLENGE_TYPE.to_owned(),
        recipient_public_key: recipient_public_key.to_base64url(),
        ephemeral_public_key: encode_b64(&ephemeral_public.to_bytes()),
        encryption: payload,
    })
}

pub fn decrypt_recovery_challenge(
    recipient_private_key: &UserPrivateKey,
    expected_aad: &AadV1,
    envelope: &RecoveryChallengeEnvelopeV1,
) -> Result<Vec<u8>, CryptoError> {
    ensure_recovery_challenge_aad(expected_aad)?;
    assert_supported_envelope_version(envelope.version)?;
    if envelope.envelope_type != DEVICE_RECOVERY_CHALLENGE_TYPE {
        return Err(CryptoError::MissingEnvelopeField("type"));
    }
    ensure_aad(expected_aad, &envelope.encryption.aad)?;
    ensure_recipient_public_key(recipient_private_key, &envelope.recipient_public_key)?;

    let ephemeral_public =
        PublicKey::from(decode_array::<KEY_LEN>(&envelope.ephemeral_public_key)?);
    let shared_secret = recipient_private_key
        .static_secret()
        .diffie_hellman(&ephemeral_public);
    ensure_contributory_shared_secret(shared_secret.as_bytes())?;
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), expected_aad)?;

    decrypt_payload_with_key(
        Key::from_slice(&wrapping_key),
        expected_aad,
        &envelope.encryption,
    )
}

pub fn unwrap_vault_key(
    private_key: &UserPrivateKey,
    expected_aad: &AadV1,
    envelope: &VaultKeyWrappingEnvelopeV1,
) -> Result<VaultKey, CryptoError> {
    assert_supported_envelope_version(envelope.version)?;
    if envelope.envelope_type != VAULT_KEY_WRAPPING_TYPE {
        return Err(CryptoError::DecryptFailed);
    }
    if envelope.wrapping.method != USER_PUBLIC_KEY_WRAPPING_METHOD {
        return Err(CryptoError::DecryptFailed);
    }

    let ephemeral_public = envelope
        .wrapping
        .ephemeral_public_key
        .as_deref()
        .ok_or(CryptoError::MissingEnvelopeField("ephemeral_public_key"))
        .and_then(UserPublicKey::from_base64url)?;
    let shared_secret = private_key
        .static_secret()
        .diffie_hellman(&ephemeral_public.public_key());
    ensure_contributory_shared_secret(shared_secret.as_bytes())?;
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), expected_aad)?;
    let crypto_envelope = CryptoEnvelopeV1 {
        version: envelope.version,
        suite: DEFAULT_SUITE.to_owned(),
        nonce: envelope.encryption.nonce.clone(),
        aad: envelope.encryption.aad.clone(),
        ciphertext: envelope.encryption.ciphertext.clone(),
    };
    let plaintext = decrypt_with_key(
        Key::from_slice(&wrapping_key),
        expected_aad,
        &crypto_envelope,
    )?;

    Ok(VaultKey(bytes_to_array(&plaintext)?))
}

pub fn encrypt_item(
    vault_key: &VaultKey,
    aad: AadV1,
    plaintext: &[u8],
) -> Result<CryptoEnvelopeV1, CryptoError> {
    let item_key = derive_item_key(vault_key, &aad)?;
    encrypt_with_key(item_key.as_key(), aad, plaintext)
}

pub fn decrypt_item(
    vault_key: &VaultKey,
    expected_aad: &AadV1,
    envelope: &CryptoEnvelopeV1,
) -> Result<Vec<u8>, CryptoError> {
    let item_key = derive_item_key(vault_key, expected_aad)?;
    decrypt_with_key(item_key.as_key(), expected_aad, envelope)
}

fn derive_item_key(vault_key: &VaultKey, aad: &AadV1) -> Result<ItemKey, CryptoError> {
    let item_id = aad
        .item_id
        .as_deref()
        .ok_or(CryptoError::MissingEnvelopeField("item_id"))?;
    let info = format!("umbra:item:v1:{item_id}");
    let hk = Hkdf::<Sha256>::new(None, vault_key.as_bytes());
    let mut output = [0u8; KEY_LEN];
    hk.expand(info.as_bytes(), &mut output)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(ItemKey(output))
}

fn derive_wrapping_key(
    shared_secret: &[u8; KEY_LEN],
    aad: &AadV1,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let aad_bytes = aad_bytes(aad)?;
    let hk = Hkdf::<Sha256>::new(Some(&aad_bytes), shared_secret);
    let mut output = [0u8; KEY_LEN];
    hk.expand(b"umbra:vault-key-wrapping:v1", &mut output)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(output)
}

fn ensure_contributory_shared_secret(shared_secret: &[u8; KEY_LEN]) -> Result<(), CryptoError> {
    if shared_secret.ct_eq(&[0u8; KEY_LEN]).into() {
        Err(CryptoError::DecryptFailed)
    } else {
        Ok(())
    }
}

fn ensure_device_bootstrap_aad(aad: &AadV1) -> Result<(), CryptoError> {
    if aad.purpose == DEVICE_BOOTSTRAP_TYPE {
        Ok(())
    } else {
        Err(CryptoError::DecryptFailed)
    }
}

fn ensure_recovery_challenge_aad(aad: &AadV1) -> Result<(), CryptoError> {
    if aad.purpose != DEVICE_RECOVERY_CHALLENGE_TYPE {
        return Err(CryptoError::DecryptFailed);
    }
    if aad.item_id.is_none() {
        return Err(CryptoError::MissingEnvelopeField("item_id"));
    }
    Ok(())
}

fn ensure_recipient_public_key(
    private_key: &UserPrivateKey,
    recipient_public_key: &str,
) -> Result<(), CryptoError> {
    let envelope_public_key = UserPublicKey::from_base64url(recipient_public_key)?;
    let derived_public_key = PublicKey::from(&private_key.static_secret());

    if envelope_public_key
        .as_bytes_array()?
        .ct_eq(&derived_public_key.to_bytes())
        .into()
    {
        Ok(())
    } else {
        Err(CryptoError::DecryptFailed)
    }
}

fn encrypt_payload_with_key(
    key: &Key,
    aad: AadV1,
    plaintext: &[u8],
) -> Result<EncryptionPayloadV1, CryptoError> {
    let nonce = Nonce::generate();
    let aad_bytes = aad_bytes(&aad)?;
    let cipher = XChaCha20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(
            nonce.as_xnonce(),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;

    Ok(EncryptionPayloadV1 {
        alg: XCHACHA20_POLY1305_ALG.to_owned(),
        nonce: nonce.to_base64url(),
        aad,
        ciphertext: encode_b64(&ciphertext),
    })
}

fn decrypt_payload_with_key(
    key: &Key,
    expected_aad: &AadV1,
    payload: &EncryptionPayloadV1,
) -> Result<Vec<u8>, CryptoError> {
    if payload.alg != XCHACHA20_POLY1305_ALG {
        return Err(CryptoError::DecryptFailed);
    }
    ensure_aad(expected_aad, &payload.aad)?;

    let nonce = decode_array::<NONCE_LEN>(&payload.nonce)?;
    let ciphertext = decode_b64(&payload.ciphertext)?;
    let aad_bytes = aad_bytes(expected_aad)?;
    let cipher = XChaCha20Poly1305::new(key);

    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

fn encrypt_with_key(
    key: &Key,
    aad: AadV1,
    plaintext: &[u8],
) -> Result<CryptoEnvelopeV1, CryptoError> {
    let payload = encrypt_payload_with_key(key, aad, plaintext)?;
    Ok(CryptoEnvelopeV1 {
        version: ENVELOPE_VERSION_V1,
        suite: DEFAULT_SUITE.to_owned(),
        nonce: payload.nonce,
        aad: payload.aad,
        ciphertext: payload.ciphertext,
    })
}

fn decrypt_with_key(
    key: &Key,
    expected_aad: &AadV1,
    envelope: &CryptoEnvelopeV1,
) -> Result<Vec<u8>, CryptoError> {
    assert_supported_envelope_version(envelope.version)?;
    if envelope.suite != DEFAULT_SUITE {
        return Err(CryptoError::DecryptFailed);
    }
    ensure_aad(expected_aad, &envelope.aad)?;

    let nonce = decode_array::<NONCE_LEN>(&envelope.nonce)?;
    let ciphertext = decode_b64(&envelope.ciphertext)?;
    let aad_bytes = aad_bytes(expected_aad)?;
    let cipher = XChaCha20Poly1305::new(key);

    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

fn ensure_aad(expected: &AadV1, actual: &AadV1) -> Result<(), CryptoError> {
    let expected = aad_bytes(expected)?;
    let actual = aad_bytes(actual)?;
    if expected.ct_eq(&actual).into() {
        Ok(())
    } else {
        Err(CryptoError::AadMismatch)
    }
}

fn aad_bytes(aad: &AadV1) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(aad).map_err(|_| CryptoError::InvalidEncoding)
}

fn encode_b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn decode_b64(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    Base64UrlUnpadded::decode_vec(encoded).map_err(|_| CryptoError::InvalidEncoding)
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], CryptoError> {
    let bytes = decode_b64(encoded)?;
    bytes_to_array(&bytes)
}

fn bytes_to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidKeyLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params(salt: Salt) -> Argon2idParams {
        fast_params_from_salt(salt.to_base64url())
    }

    fn fast_params_from_salt(salt: impl Into<String>) -> Argon2idParams {
        Argon2idParams {
            profile: KdfProfile::Custom,
            memory_mib: 64,
            iterations: 3,
            parallelism: 1,
            salt: salt.into(),
        }
    }

    fn bootstrap_bundle() -> DeviceBootstrapBundleV1 {
        let password = MasterPassword::new("correct horse battery staple");
        let user_secret_key = UserSecretKey::generate();
        let kdf_params = fast_params_from_salt(Salt::generate().to_base64url());
        let account_kek = derive_account_kek(&password, &user_secret_key, &kdf_params).unwrap();
        let account = generate_user_keypair();
        let encrypted_user_private_key = encrypt_user_private_key(
            &account_kek,
            &account.private_key,
            AadV1::user_private_key(account.public_key.to_base64url()),
        )
        .unwrap();

        DeviceBootstrapBundleV1 {
            version: ENVELOPE_VERSION_V1,
            user_secret_key: user_secret_key.to_base64url(),
            kdf_params,
            encrypted_user_private_key,
            account_public_key: account.public_key.to_base64url(),
            default_vault_id: Some("vault-1".to_owned()),
        }
    }

    #[test]
    fn kdf_params_are_serializable() {
        let params = Argon2idParams::balanced_with_salt("salt");
        let json = serde_json::to_string(&params).unwrap();
        let decoded: Argon2idParams = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, params);
    }

    #[test]
    fn argon2id_uses_salt() {
        let password = MasterPassword::new("correct horse battery staple");
        let secret_key = UserSecretKey::from_bytes([7u8; KEY_LEN]);
        let first = derive_account_kek(
            &password,
            &secret_key,
            &fast_params(Salt::from_bytes([1u8; 16])),
        )
        .unwrap();
        let second = derive_account_kek(
            &password,
            &secret_key,
            &fast_params(Salt::from_bytes([2u8; 16])),
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn private_key_encrypt_decrypt_roundtrip() {
        let password = MasterPassword::new("password");
        let secret_key = UserSecretKey::from_bytes([3u8; KEY_LEN]);
        let kek = derive_account_kek(
            &password,
            &secret_key,
            &fast_params(Salt::from_bytes([4u8; 16])),
        )
        .unwrap();
        let keypair = generate_user_keypair();
        let aad = AadV1::user_private_key("user-1");

        let envelope = encrypt_user_private_key(&kek, &keypair.private_key, aad.clone()).unwrap();
        let decrypted = decrypt_user_private_key(&kek, &aad, &envelope).unwrap();

        assert_eq!(decrypted, keypair.private_key);
    }

    #[test]
    fn vault_key_wrap_unwrap_roundtrip() {
        let keypair = generate_user_keypair();
        let vault_key = generate_vault_key();
        let aad = AadV1::vault_key_wrapping("vault-1");

        let envelope =
            wrap_vault_key_for_user(&keypair.public_key, &vault_key, aad.clone()).unwrap();
        let unwrapped = unwrap_vault_key(&keypair.private_key, &aad, &envelope).unwrap();

        assert_eq!(unwrapped, vault_key);
    }

    #[test]
    fn device_bootstrap_bundle_roundtrips() {
        let recipient = generate_user_keypair();
        let aad = AadV1::device_bootstrap("device-1");
        let bundle = bootstrap_bundle();

        let envelope =
            encrypt_device_bootstrap_bundle(&recipient.public_key, aad.clone(), &bundle).unwrap();
        let decrypted =
            decrypt_device_bootstrap_bundle(&recipient.private_key, &aad, &envelope).unwrap();

        assert_eq!(envelope.version, ENVELOPE_VERSION_V1);
        assert_eq!(envelope.envelope_type, "device_bootstrap");
        assert_eq!(
            envelope.recipient_public_key,
            recipient.public_key.to_base64url()
        );
        assert_eq!(envelope.encryption.alg, XCHACHA20_POLY1305_ALG);
        assert_eq!(decrypted, bundle);

        let debug = format!("{bundle:?}");
        assert!(!debug.contains(&bundle.user_secret_key));
    }

    #[test]
    fn device_bootstrap_bundle_fails_with_wrong_key_or_aad() {
        let recipient = generate_user_keypair();
        let wrong_recipient = generate_user_keypair();
        let aad = AadV1::device_bootstrap("device-1");
        let bundle = bootstrap_bundle();
        let envelope =
            encrypt_device_bootstrap_bundle(&recipient.public_key, aad.clone(), &bundle).unwrap();

        assert!(matches!(
            decrypt_device_bootstrap_bundle(&wrong_recipient.private_key, &aad, &envelope),
            Err(CryptoError::DecryptFailed)
        ));

        assert!(matches!(
            decrypt_device_bootstrap_bundle(
                &recipient.private_key,
                &AadV1::device_bootstrap("device-2"),
                &envelope
            ),
            Err(CryptoError::AadMismatch)
        ));
    }

    #[test]
    fn bootstrap_decrypt_fails_if_recipient_public_key_metadata_is_tampered() {
        let recipient = generate_user_keypair();
        let other_recipient = generate_user_keypair();
        let aad = AadV1::device_bootstrap("device-1");
        let bundle = bootstrap_bundle();
        let mut envelope =
            encrypt_device_bootstrap_bundle(&recipient.public_key, aad.clone(), &bundle).unwrap();
        envelope.recipient_public_key = other_recipient.public_key.to_base64url();

        assert!(matches!(
            decrypt_device_bootstrap_bundle(&recipient.private_key, &aad, &envelope),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn bootstrap_rejects_wrong_purpose_aad() {
        let recipient = generate_user_keypair();
        let wrong_aad = AadV1::vault_key_wrapping("device-1");
        let bundle = bootstrap_bundle();

        assert!(matches!(
            encrypt_device_bootstrap_bundle(&recipient.public_key, wrong_aad.clone(), &bundle),
            Err(CryptoError::DecryptFailed)
        ));

        let aad = AadV1::device_bootstrap("device-1");
        let envelope =
            encrypt_device_bootstrap_bundle(&recipient.public_key, aad, &bundle).unwrap();

        assert!(matches!(
            decrypt_device_bootstrap_bundle(&recipient.private_key, &wrong_aad, &envelope),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn recovery_challenge_roundtrips() {
        let recipient = generate_user_keypair();
        let aad = AadV1::recovery_challenge("device-1", "challenge-1");
        let challenge = b"challenge-response";

        let envelope =
            encrypt_recovery_challenge(&recipient.public_key, aad.clone(), challenge).unwrap();
        let decrypted =
            decrypt_recovery_challenge(&recipient.private_key, &aad, &envelope).unwrap();

        assert_eq!(envelope.version, ENVELOPE_VERSION_V1);
        assert_eq!(envelope.envelope_type, "device_recovery_challenge");
        assert_eq!(
            envelope.recipient_public_key,
            recipient.public_key.to_base64url()
        );
        assert_eq!(envelope.encryption.alg, XCHACHA20_POLY1305_ALG);
        assert_eq!(decrypted, challenge);
    }

    #[test]
    fn recovery_decrypt_fails_if_recipient_public_key_metadata_is_tampered() {
        let recipient = generate_user_keypair();
        let other_recipient = generate_user_keypair();
        let aad = AadV1::recovery_challenge("device-1", "challenge-1");
        let mut envelope =
            encrypt_recovery_challenge(&recipient.public_key, aad.clone(), b"challenge").unwrap();
        envelope.recipient_public_key = other_recipient.public_key.to_base64url();

        assert!(matches!(
            decrypt_recovery_challenge(&recipient.private_key, &aad, &envelope),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn recovery_rejects_wrong_purpose_aad() {
        let recipient = generate_user_keypair();
        let wrong_aad = AadV1::device_bootstrap("device-1");

        assert!(matches!(
            encrypt_recovery_challenge(&recipient.public_key, wrong_aad.clone(), b"challenge"),
            Err(CryptoError::DecryptFailed)
        ));

        let mut missing_challenge_id = AadV1::recovery_challenge("device-1", "challenge-1");
        missing_challenge_id.item_id = None;
        assert!(matches!(
            encrypt_recovery_challenge(
                &recipient.public_key,
                missing_challenge_id.clone(),
                b"challenge"
            ),
            Err(CryptoError::MissingEnvelopeField("item_id"))
        ));

        let aad = AadV1::recovery_challenge("device-1", "challenge-1");
        let envelope =
            encrypt_recovery_challenge(&recipient.public_key, aad, b"challenge").unwrap();

        assert!(matches!(
            decrypt_recovery_challenge(&recipient.private_key, &wrong_aad, &envelope),
            Err(CryptoError::DecryptFailed)
        ));
        assert!(matches!(
            decrypt_recovery_challenge(&recipient.private_key, &missing_challenge_id, &envelope),
            Err(CryptoError::MissingEnvelopeField("item_id"))
        ));
    }

    #[test]
    fn rejects_non_contributory_shared_secret() {
        let recipient = generate_user_keypair();
        let aad = AadV1::device_bootstrap("device-1");
        let bundle = bootstrap_bundle();
        let all_zero_public_key = UserPublicKey::from_bytes([0u8; KEY_LEN]);

        assert!(matches!(
            encrypt_device_bootstrap_bundle(&all_zero_public_key, aad.clone(), &bundle),
            Err(CryptoError::DecryptFailed)
        ));

        let mut envelope =
            encrypt_device_bootstrap_bundle(&recipient.public_key, aad.clone(), &bundle).unwrap();
        envelope.ephemeral_public_key = encode_b64(&[0u8; KEY_LEN]);

        assert!(matches!(
            decrypt_device_bootstrap_bundle(&recipient.private_key, &aad, &envelope),
            Err(CryptoError::DecryptFailed)
        ));

        let recovery_aad = AadV1::recovery_challenge("device-1", "challenge-1");
        assert!(matches!(
            encrypt_recovery_challenge(&all_zero_public_key, recovery_aad.clone(), b"challenge"),
            Err(CryptoError::DecryptFailed)
        ));

        let mut recovery_envelope =
            encrypt_recovery_challenge(&recipient.public_key, recovery_aad.clone(), b"challenge")
                .unwrap();
        recovery_envelope.ephemeral_public_key = encode_b64(&[0u8; KEY_LEN]);

        assert!(matches!(
            decrypt_recovery_challenge(&recipient.private_key, &recovery_aad, &recovery_envelope),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn item_encrypt_decrypt_roundtrip() {
        let vault_key = generate_vault_key();
        let aad = AadV1::item("vault-1", "item-1", 1, "login");
        let envelope = encrypt_item(&vault_key, aad.clone(), b"hello").unwrap();
        let plaintext = decrypt_item(&vault_key, &aad, &envelope).unwrap();

        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn item_decrypt_fails_with_aad_changed() {
        let vault_key = generate_vault_key();
        let aad = AadV1::item("vault-1", "item-1", 1, "login");
        let envelope = encrypt_item(&vault_key, aad.clone(), b"hello").unwrap();
        let wrong_aad = AadV1::item("vault-1", "item-1", 2, "login");

        assert_eq!(
            decrypt_item(&vault_key, &wrong_aad, &envelope),
            Err(CryptoError::AadMismatch)
        );
    }

    #[test]
    fn item_decrypt_fails_with_wrong_vault_id() {
        let vault_key = generate_vault_key();
        let aad = AadV1::item("vault-1", "item-1", 1, "login");
        let envelope = encrypt_item(&vault_key, aad, b"hello").unwrap();
        let wrong_aad = AadV1::item("vault-2", "item-1", 1, "login");

        assert_eq!(
            decrypt_item(&vault_key, &wrong_aad, &envelope),
            Err(CryptoError::AadMismatch)
        );
    }

    #[test]
    fn item_decrypt_fails_with_wrong_item_id() {
        let vault_key = generate_vault_key();
        let aad = AadV1::item("vault-1", "item-1", 1, "login");
        let envelope = encrypt_item(&vault_key, aad, b"hello").unwrap();
        let wrong_aad = AadV1::item("vault-1", "item-2", 1, "login");

        assert_eq!(
            decrypt_item(&vault_key, &wrong_aad, &envelope),
            Err(CryptoError::AadMismatch)
        );
    }

    #[test]
    fn item_decrypt_fails_with_nonce_changed() {
        let vault_key = generate_vault_key();
        let aad = AadV1::item("vault-1", "item-1", 1, "login");
        let mut envelope = encrypt_item(&vault_key, aad.clone(), b"hello").unwrap();
        envelope.nonce = Nonce::generate().to_base64url();

        assert_eq!(
            decrypt_item(&vault_key, &aad, &envelope),
            Err(CryptoError::DecryptFailed)
        );
    }

    #[test]
    fn item_decrypt_fails_with_ciphertext_changed() {
        let vault_key = generate_vault_key();
        let aad = AadV1::item("vault-1", "item-1", 1, "login");
        let mut envelope = encrypt_item(&vault_key, aad.clone(), b"hello").unwrap();
        let mut ciphertext = decode_b64(&envelope.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        envelope.ciphertext = encode_b64(&ciphertext);

        assert_eq!(
            decrypt_item(&vault_key, &aad, &envelope),
            Err(CryptoError::DecryptFailed)
        );
    }

    #[test]
    fn sensitive_debug_is_redacted() {
        let secret = UserSecretKey::from_bytes([9u8; KEY_LEN]);

        assert_eq!(format!("{secret:?}"), "UserSecretKey([redacted])");
        assert!(!format!("{secret:?}").contains('9'));
    }

    #[test]
    fn local_unlock_state_encrypt_decrypt_roundtrip() {
        let key = LocalUnlockKey::generate();
        let aad = AadV1::local_unlock_state("personal", "device-1");
        let plaintext = br#"{"version":1,"vault_keys":{}}"#;

        let envelope = encrypt_local_unlock_state(&key, aad.clone(), plaintext).unwrap();
        let decrypted = decrypt_local_unlock_state(&key, &aad, &envelope).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(
            LocalUnlockKey::from_base64url(&key.to_base64url()).unwrap(),
            key
        );
    }

    #[test]
    fn local_unlock_state_decrypt_fails_with_wrong_aad() {
        let key = LocalUnlockKey::generate();
        let aad = AadV1::local_unlock_state("personal", "device-1");
        let wrong_aad = AadV1::local_unlock_state("personal", "device-2");

        let envelope = encrypt_local_unlock_state(&key, aad, b"secret").unwrap();

        assert!(decrypt_local_unlock_state(&key, &wrong_aad, &envelope).is_err());
    }
}
