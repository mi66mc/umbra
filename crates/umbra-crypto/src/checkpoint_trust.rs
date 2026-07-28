use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{DeviceCheckpointTrustAnchorV1, UserPrivateKey, UserPublicKey};

const TRUST_BUNDLE_VERSION: u16 = 1;
const TRUST_BUNDLE_KDF_DOMAIN: &[u8] = b"umbra/checkpoint-trust-bundle/signing-key/v1";
const TRUST_BUNDLE_SIGNATURE_DOMAIN: &[u8] = b"umbra/checkpoint-trust-bundle/payload/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointTrustBundleV1 {
    pub version: u16,
    pub account_public_key: String,
    pub trusted_checkpoint_devices: Vec<DeviceCheckpointTrustAnchorV1>,
    pub signature: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointTrustError {
    #[error("checkpoint trust bundle has an unsupported version")]
    UnsupportedVersion,
    #[error("checkpoint trust bundle account does not match the unlocked account")]
    AccountMismatch,
    #[error("checkpoint trust bundle contains a duplicate device id")]
    DuplicateDevice,
    #[error("checkpoint trust bundle encoding is invalid")]
    InvalidEncoding,
    #[error("checkpoint trust bundle signature is invalid")]
    InvalidSignature,
}

#[derive(Serialize)]
struct CanonicalCheckpointTrustBundle<'a> {
    version: u16,
    account_public_key: &'a str,
    trusted_checkpoint_devices: &'a [DeviceCheckpointTrustAnchorV1],
}

pub fn authenticate_checkpoint_trust_bundle(
    account_private_key: &UserPrivateKey,
    account_public_key: &UserPublicKey,
    mut anchors: Vec<DeviceCheckpointTrustAnchorV1>,
) -> Result<CheckpointTrustBundleV1, CheckpointTrustError> {
    ensure_account_pair(account_private_key, account_public_key)?;
    sort_and_validate_anchors(&mut anchors)?;
    let account_public_key = account_public_key.to_base64url();
    let canonical = canonical_payload(&account_public_key, &anchors)?;
    let signing_key = trust_bundle_signing_key(account_private_key)?;
    let mut message = Vec::with_capacity(TRUST_BUNDLE_SIGNATURE_DOMAIN.len() + canonical.len());
    message.extend_from_slice(TRUST_BUNDLE_SIGNATURE_DOMAIN);
    message.extend_from_slice(&canonical);
    let signature = signing_key.sign(&message);
    message.zeroize();

    Ok(CheckpointTrustBundleV1 {
        version: TRUST_BUNDLE_VERSION,
        account_public_key,
        trusted_checkpoint_devices: anchors,
        signature: Base64UrlUnpadded::encode_string(&signature.to_bytes()),
    })
}

pub fn verify_checkpoint_trust_bundle(
    account_private_key: &UserPrivateKey,
    account_public_key: &UserPublicKey,
    bundle: &CheckpointTrustBundleV1,
) -> Result<Vec<DeviceCheckpointTrustAnchorV1>, CheckpointTrustError> {
    if bundle.version != TRUST_BUNDLE_VERSION {
        return Err(CheckpointTrustError::UnsupportedVersion);
    }
    ensure_account_pair(account_private_key, account_public_key)?;
    if bundle.account_public_key != account_public_key.to_base64url() {
        return Err(CheckpointTrustError::AccountMismatch);
    }

    let mut anchors = bundle.trusted_checkpoint_devices.clone();
    sort_and_validate_anchors(&mut anchors)?;
    let canonical = canonical_payload(&bundle.account_public_key, &anchors)?;
    let signing_key = trust_bundle_signing_key(account_private_key)?;
    let signature_bytes = Base64UrlUnpadded::decode_vec(&bundle.signature)
        .map_err(|_| CheckpointTrustError::InvalidEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| CheckpointTrustError::InvalidSignature)?;
    let mut message = Vec::with_capacity(TRUST_BUNDLE_SIGNATURE_DOMAIN.len() + canonical.len());
    message.extend_from_slice(TRUST_BUNDLE_SIGNATURE_DOMAIN);
    message.extend_from_slice(&canonical);
    let result = signing_key
        .verifying_key()
        .verify(&message, &signature)
        .map_err(|_| CheckpointTrustError::InvalidSignature);
    message.zeroize();
    result.map(|()| anchors)
}

fn canonical_payload(
    account_public_key: &str,
    anchors: &[DeviceCheckpointTrustAnchorV1],
) -> Result<Vec<u8>, CheckpointTrustError> {
    serde_json::to_vec(&CanonicalCheckpointTrustBundle {
        version: TRUST_BUNDLE_VERSION,
        account_public_key,
        trusted_checkpoint_devices: anchors,
    })
    .map_err(|_| CheckpointTrustError::InvalidEncoding)
}

fn sort_and_validate_anchors(
    anchors: &mut [DeviceCheckpointTrustAnchorV1],
) -> Result<(), CheckpointTrustError> {
    anchors.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    if anchors
        .windows(2)
        .any(|pair| pair[0].device_id == pair[1].device_id)
    {
        return Err(CheckpointTrustError::DuplicateDevice);
    }
    Ok(())
}

fn ensure_account_pair(
    private_key: &UserPrivateKey,
    public_key: &UserPublicKey,
) -> Result<(), CheckpointTrustError> {
    let private_bytes = private_key
        .as_bytes_array()
        .map_err(|_| CheckpointTrustError::InvalidEncoding)?;
    let derived = PublicKey::from(&StaticSecret::from(private_bytes));
    if derived.to_bytes()
        != public_key
            .as_bytes_array()
            .map_err(|_| CheckpointTrustError::InvalidEncoding)?
    {
        return Err(CheckpointTrustError::AccountMismatch);
    }
    Ok(())
}

fn trust_bundle_signing_key(
    account_private_key: &UserPrivateKey,
) -> Result<SigningKey, CheckpointTrustError> {
    let private_bytes = account_private_key
        .as_bytes_array()
        .map_err(|_| CheckpointTrustError::InvalidEncoding)?;
    let hkdf = Hkdf::<Sha256>::new(Some(TRUST_BUNDLE_KDF_DOMAIN), &private_bytes);
    let mut seed = [0u8; 32];
    hkdf.expand(b"ed25519", &mut seed)
        .map_err(|_| CheckpointTrustError::InvalidEncoding)?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceCheckpointTrustAnchorV1, generate_user_keypair};

    fn anchors() -> Vec<DeviceCheckpointTrustAnchorV1> {
        vec![
            DeviceCheckpointTrustAnchorV1 {
                device_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                public_key: "device-key-2".to_owned(),
                revoked: false,
            },
            DeviceCheckpointTrustAnchorV1 {
                device_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                public_key: "device-key-1".to_owned(),
                revoked: true,
            },
        ]
    }

    #[test]
    fn account_authenticated_trust_bundle_roundtrips_in_canonical_order() {
        let account = generate_user_keypair();

        let bundle = authenticate_checkpoint_trust_bundle(
            &account.private_key,
            &account.public_key,
            anchors(),
        )
        .unwrap();
        let verified =
            verify_checkpoint_trust_bundle(&account.private_key, &account.public_key, &bundle)
                .unwrap();

        assert_eq!(
            verified
                .iter()
                .map(|anchor| anchor.device_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002"
            ]
        );
    }

    #[test]
    fn trust_bundle_rejects_anchor_tampering_and_wrong_account() {
        let account = generate_user_keypair();
        let other_account = generate_user_keypair();
        let mut bundle = authenticate_checkpoint_trust_bundle(
            &account.private_key,
            &account.public_key,
            anchors(),
        )
        .unwrap();
        bundle.trusted_checkpoint_devices[0].public_key = "attacker-key".to_owned();

        assert!(
            verify_checkpoint_trust_bundle(&account.private_key, &account.public_key, &bundle)
                .is_err()
        );
        assert!(
            verify_checkpoint_trust_bundle(
                &other_account.private_key,
                &other_account.public_key,
                &bundle
            )
            .is_err()
        );
    }

    #[test]
    fn trust_bundle_rejects_duplicate_device_ids() {
        let account = generate_user_keypair();
        let mut duplicate = anchors();
        duplicate.push(duplicate[0].clone());

        assert!(
            authenticate_checkpoint_trust_bundle(
                &account.private_key,
                &account.public_key,
                duplicate
            )
            .is_err()
        );
    }
}
