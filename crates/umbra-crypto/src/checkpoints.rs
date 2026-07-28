use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use umbra_protocol::SyncCheckpoint;

const DOMAIN: &[u8] = b"UMBRA-SYNC-CHECKPOINT-V1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("checkpoint encoding is invalid")]
    Encoding,
    #[error("checkpoint signature is invalid")]
    InvalidSignature,
}

pub fn canonical_checkpoint_payload(
    checkpoint: &SyncCheckpoint,
) -> Result<Vec<u8>, CheckpointError> {
    let commitment = Base64UrlUnpadded::decode_vec(&checkpoint.state_commitment)
        .map_err(|_| CheckpointError::Encoding)?;
    if commitment.len() != 32 {
        return Err(CheckpointError::Encoding);
    }
    let previous = checkpoint
        .previous_checkpoint_hash
        .as_deref()
        .map(Base64UrlUnpadded::decode_vec)
        .transpose()
        .map_err(|_| CheckpointError::Encoding)?;
    if previous.as_ref().is_some_and(|value| value.len() != 32) {
        return Err(CheckpointError::Encoding);
    }
    let mut output = Vec::with_capacity(DOMAIN.len() + 16 + 8 + 32 + 1 + 32 + 16);
    output.extend_from_slice(DOMAIN);
    output.extend_from_slice(checkpoint.vault_id.as_bytes());
    output.extend_from_slice(&checkpoint.vault_revision.to_be_bytes());
    output.extend_from_slice(&commitment);
    match previous {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value);
        }
        None => output.push(0),
    }
    output.extend_from_slice(checkpoint.author_device_id.as_bytes());
    Ok(output)
}

pub fn checkpoint_hash(checkpoint: &SyncCheckpoint) -> Result<String, CheckpointError> {
    Ok(Base64UrlUnpadded::encode_string(&Sha256::digest(
        canonical_checkpoint_payload(checkpoint)?,
    )))
}

pub fn sign_checkpoint(
    mut checkpoint: SyncCheckpoint,
    signing_key: &SigningKey,
) -> Result<SyncCheckpoint, CheckpointError> {
    let signature = signing_key.sign(&canonical_checkpoint_payload(&checkpoint)?);
    checkpoint.signature = Base64UrlUnpadded::encode_string(&signature.to_bytes());
    Ok(checkpoint)
}

pub fn verify_checkpoint(
    checkpoint: &SyncCheckpoint,
    key: &VerifyingKey,
) -> Result<(), CheckpointError> {
    let bytes = Base64UrlUnpadded::decode_vec(&checkpoint.signature)
        .map_err(|_| CheckpointError::InvalidSignature)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| CheckpointError::InvalidSignature)?;
    key.verify(&canonical_checkpoint_payload(checkpoint)?, &signature)
        .map_err(|_| CheckpointError::InvalidSignature)
}

pub fn state_commitment(entries: impl IntoIterator<Item = Vec<u8>>) -> String {
    let mut entries: Vec<_> = entries.into_iter().collect();
    entries.sort();
    let mut hash = Sha256::new();
    hash.update(b"UMBRA-SYNC-STATE-V1");
    for entry in entries {
        hash.update((entry.len() as u64).to_be_bytes());
        hash.update(entry);
    }
    Base64UrlUnpadded::encode_string(&hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use uuid::Uuid;

    #[test]
    fn signed_checkpoint_rejects_a_changed_revision() {
        let key = SigningKey::generate(&mut OsRng);
        let mut checkpoint = sign_checkpoint(
            SyncCheckpoint {
                vault_id: Uuid::new_v4(),
                vault_revision: 3,
                state_commitment: state_commitment([b"ciphertext-hash".to_vec()]),
                previous_checkpoint_hash: None,
                author_device_id: Uuid::new_v4(),
                signature: String::new(),
            },
            &key,
        )
        .unwrap();
        verify_checkpoint(&checkpoint, &key.verifying_key()).unwrap();
        checkpoint.vault_revision = 4;
        assert_eq!(
            verify_checkpoint(&checkpoint, &key.verifying_key()),
            Err(CheckpointError::InvalidSignature)
        );
    }
}
