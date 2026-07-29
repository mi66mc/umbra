use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::SigningKey;
use fs4::fs_std::FileExt;
use rusqlite::{Connection, DatabaseName, OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use umbra_core::VaultKind;
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, LocalUnlockKey, decrypt_local_unlock_state, encrypt_local_unlock_state,
};
use umbra_protocol::{SyncCheckpoint, VaultKeyWrappingMetadata, VaultSyncChanges};

use crate::error::CliError;

pub struct LocalCache {
    connection: Connection,
    profile: String,
    persistence: Option<CachePersistence>,
}

const CACHE_FORMAT_VERSION: u16 = 1;
const KEYRING_SERVICE: &str = "umbra";

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedCacheV1 {
    version: u16,
    envelope: CryptoEnvelopeV1,
}

trait CacheKeyStore: Send + Sync {
    fn get(&self, profile: &str) -> Result<Option<LocalUnlockKey>, CliError>;
    fn set(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError>;
    fn clear(&self, profile: &str) -> Result<(), CliError>;
}

struct KeyringCacheKeyStore;

impl CacheKeyStore for KeyringCacheKeyStore {
    fn get(&self, profile: &str) -> Result<Option<LocalUnlockKey>, CliError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &cache_keyring_account(profile))?;
        match entry.get_password() {
            Ok(value) => Ok(Some(LocalUnlockKey::from_base64url(&value)?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn set(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError> {
        keyring::Entry::new(KEYRING_SERVICE, &cache_keyring_account(profile))?
            .set_password(&key.to_base64url())?;
        Ok(())
    }

    fn clear(&self, profile: &str) -> Result<(), CliError> {
        match keyring::Entry::new(KEYRING_SERVICE, &cache_keyring_account(profile))?
            .delete_credential()
        {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

struct CachePersistence {
    encrypted_path: PathBuf,
    lock_path: PathBuf,
    expected_snapshot_hash: RefCell<Option<[u8; 32]>>,
    key_store: Arc<dyn CacheKeyStore>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedVault {
    pub vault_id: uuid::Uuid,
    pub name: String,
    pub kind: String,
    pub latest_vault_revision: i64,
    pub latest_access_revision: i64,
    pub current_key_generation: i64,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSyncState {
    pub vault_id: uuid::Uuid,
    pub latest_vault_revision: i64,
    pub latest_access_revision: i64,
    pub synced_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedItemRevision {
    pub vault_id: uuid::Uuid,
    pub item_id: uuid::Uuid,
    pub revision: i64,
    pub vault_revision: i64,
    pub key_generation: i64,
    pub author_user_id: Option<uuid::Uuid>,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedItemConflict {
    pub conflict_id: uuid::Uuid,
    pub vault_id: uuid::Uuid,
    pub item_id: uuid::Uuid,
    pub base_revision: i64,
    pub current_revision: i64,
    pub candidate_kind: String,
    pub candidate_envelope: Option<serde_json::Value>,
    pub author_user_id: Option<uuid::Uuid>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[allow(dead_code)]
pub struct CachedKeyWrapping {
    pub id: uuid::Uuid,
    pub vault_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub device_id: Option<uuid::Uuid>,
    pub wrapping_type: String,
    pub envelope: serde_json::Value,
    pub key_generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CacheStatus {
    pub profile: String,
    pub synced_vault_count: i64,
    pub item_revision_count: i64,
    pub key_wrapping_count: i64,
    pub sync_state_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrityFinding {
    pub vault_id: uuid::Uuid,
    pub revision: i64,
    pub checkpoint_hash: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflicting_checkpoint_hash: Option<String>,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCheckpointDevice {
    pub device_id: uuid::Uuid,
    pub public_key: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCheckpoint {
    pub checkpoint_hash: String,
    pub checkpoint: SyncCheckpoint,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultIntegrityState {
    pub vault_id: uuid::Uuid,
    pub unsafe_sync: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_head: Option<VerifiedCheckpoint>,
    pub findings: Vec<IntegrityFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointForensicsBundle {
    pub version: u16,
    pub vault_id: uuid::Uuid,
    pub unsafe_sync: bool,
    pub verified_checkpoints: Vec<SyncCheckpoint>,
    pub observed_checkpoints: Vec<SyncCheckpoint>,
    pub findings: Vec<IntegrityFinding>,
}

impl LocalCache {
    pub fn open(profile: &str) -> Result<Self, CliError> {
        let dir = profile_cache_dir(profile);
        std::fs::create_dir_all(&dir)?;
        Self::open_path(profile, dir.join("cache.db"))
    }

    pub fn open_path(profile: &str, path: PathBuf) -> Result<Self, CliError> {
        Self::open_path_with_key_store(profile, path, Arc::new(KeyringCacheKeyStore))
    }

    fn open_path_with_key_store(
        profile: &str,
        legacy_path: PathBuf,
        key_store: Arc<dyn CacheKeyStore>,
    ) -> Result<Self, CliError> {
        let encrypted_path = legacy_path.with_file_name("cache.enc");
        if legacy_path.exists() && !encrypted_path.exists() {
            return Err(CliError::Input(
                "legacy plaintext cache detected; back it up, remove it intentionally, then sync again",
            ));
        }
        let mut connection = Connection::open_in_memory()?;
        let expected_snapshot_hash = snapshot_hash(&encrypted_path)?;
        if encrypted_path.exists() {
            let Some(key) = key_store.get(profile)? else {
                return Err(CliError::Input(
                    "encrypted cache key is unavailable; restore the OS keychain entry or clear the cache intentionally",
                ));
            };
            let stored: PersistedCacheV1 = serde_json::from_slice(&std::fs::read(&encrypted_path)?)
                .map_err(|_| CliError::Input("encrypted cache format is invalid; restore a known-good cache or clear it intentionally"))?;
            if stored.version != CACHE_FORMAT_VERSION {
                return Err(CliError::Input(
                    "encrypted cache format version is unsupported; restore a compatible client or clear the cache intentionally",
                ));
            }
            let bytes = decrypt_local_unlock_state(&key, &cache_aad(profile), &stored.envelope)
                .map_err(|_| CliError::Input("encrypted cache authentication failed; do not trust this cache; restore it or clear it intentionally"))?;
            deserialize_database(&mut connection, bytes)?;
        }
        let cache = Self {
            connection,
            profile: profile.to_owned(),
            persistence: Some(CachePersistence {
                lock_path: encrypted_path.with_file_name("cache.lock"),
                encrypted_path,
                expected_snapshot_hash: RefCell::new(expected_snapshot_hash),
                key_store,
            }),
        };
        cache.create_schema()?;
        Ok(cache)
    }

    #[cfg(test)]
    pub fn open_in_memory(profile: &str) -> Result<Self, CliError> {
        let connection = Connection::open_in_memory()?;
        let cache = Self {
            connection,
            profile: profile.to_owned(),
            persistence: None,
        };
        cache.create_schema()?;
        Ok(cache)
    }

    #[cfg(test)]
    pub fn table_names(&self) -> Result<Vec<String>, CliError> {
        let mut statement = self
            .connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    #[cfg(test)]
    pub fn apply_sync_changes(&mut self, changes: &VaultSyncChanges) -> Result<(), CliError> {
        let tx = self.connection.transaction()?;
        apply_sync_changes_transaction(&tx, changes)?;
        tx.commit()?;
        Ok(())
    }

    pub fn integrity_findings(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<IntegrityFinding>, CliError> {
        let mut statement = self.connection.prepare(
            "SELECT vault_id, revision, checkpoint_hash, code, conflicting_checkpoint_hash, observed_at
             FROM sync_integrity_findings WHERE vault_id = ?1 ORDER BY id ASC",
        )?;
        let rows = statement.query_map(params![vault_id.to_string()], |row| {
            Ok(IntegrityFinding {
                vault_id: parse_uuid(row.get::<_, String>(0)?)?,
                revision: row.get(1)?,
                checkpoint_hash: row.get(2)?,
                code: row.get(3)?,
                conflicting_checkpoint_hash: row.get(4)?,
                observed_at: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn record_trusted_checkpoint_device(
        &self,
        device: &TrustedCheckpointDevice,
    ) -> Result<(), CliError> {
        let existing = self
            .connection
            .query_row(
                "SELECT public_key, revoked FROM trusted_checkpoint_devices WHERE device_id = ?1",
                params![device.device_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        if let Some((public_key, revoked)) = existing {
            if public_key != device.public_key {
                return Err(CliError::Input(
                    "trusted checkpoint device key cannot be replaced",
                ));
            }
            let revoked = revoked || device.revoked;
            self.connection.execute(
                "UPDATE trusted_checkpoint_devices SET revoked = ?2 WHERE device_id = ?1",
                params![device.device_id.to_string(), revoked],
            )?;
            self.persist()?;
            return Ok(());
        }
        self.connection.execute(
            "INSERT INTO trusted_checkpoint_devices (device_id, public_key, revoked, trusted_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                device.device_id.to_string(),
                device.public_key,
                device.revoked,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        self.persist()?;
        Ok(())
    }

    pub fn trusted_checkpoint_devices(&self) -> Result<Vec<TrustedCheckpointDevice>, CliError> {
        let mut statement = self.connection.prepare(
            "SELECT device_id, public_key, revoked
             FROM trusted_checkpoint_devices ORDER BY device_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(TrustedCheckpointDevice {
                device_id: parse_uuid(row.get::<_, String>(0)?)?,
                public_key: row.get(1)?,
                revoked: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn is_sync_unsafe(&self, vault_id: uuid::Uuid) -> Result<bool, CliError> {
        Ok(self
            .connection
            .query_row(
                "SELECT unsafe FROM sync_integrity_state WHERE vault_id = ?1",
                params![vault_id.to_string()],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false))
    }

    pub fn integrity_state(&self, vault_id: uuid::Uuid) -> Result<VaultIntegrityState, CliError> {
        let verified_head = self
            .connection
            .query_row(
                "SELECT checkpoint_hash, checkpoint_json, verified_at
                 FROM verified_checkpoint_heads WHERE vault_id = ?1",
                params![vault_id.to_string()],
                verified_checkpoint_from_row,
            )
            .optional()?;
        Ok(VaultIntegrityState {
            vault_id,
            unsafe_sync: self.is_sync_unsafe(vault_id)?,
            verified_head,
            findings: self.integrity_findings(vault_id)?,
        })
    }

    pub fn export_checkpoint_evidence(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<CheckpointForensicsBundle, CliError> {
        Ok(CheckpointForensicsBundle {
            version: 1,
            vault_id,
            unsafe_sync: self.is_sync_unsafe(vault_id)?,
            verified_checkpoints: self
                .checkpoints_from_table("verified_sync_checkpoints", vault_id)?,
            observed_checkpoints: self
                .checkpoints_from_table("observed_sync_checkpoints", vault_id)?,
            findings: self.integrity_findings(vault_id)?,
        })
    }

    fn checkpoints_from_table(
        &self,
        table: &str,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<SyncCheckpoint>, CliError> {
        let sql = match table {
            "verified_sync_checkpoints" => {
                "SELECT checkpoint_json FROM verified_sync_checkpoints
                 WHERE vault_id = ?1 ORDER BY revision ASC, checkpoint_hash ASC"
            }
            "observed_sync_checkpoints" => {
                "SELECT checkpoint_json FROM observed_sync_checkpoints
                 WHERE vault_id = ?1 ORDER BY revision ASC, checkpoint_hash ASC"
            }
            _ => return Err(CliError::Input("unknown checkpoint evidence table")),
        };
        let mut statement = self.connection.prepare(sql)?;
        let rows = statement.query_map(params![vault_id.to_string()], |row| {
            parse_json_as(row.get::<_, String>(0)?)
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    #[cfg(test)]
    pub(crate) fn projected_state_commitment(
        &mut self,
        changes: &VaultSyncChanges,
    ) -> Result<String, CliError> {
        let tx = self.connection.transaction()?;
        apply_sync_changes_transaction(&tx, changes)?;
        let commitment = state_commitment_transaction(&tx, changes.vault_id)?;
        tx.rollback()?;
        Ok(commitment)
    }

    pub fn verify_and_record_checkpoints(
        &mut self,
        changes: &VaultSyncChanges,
        checkpoints: &[SyncCheckpoint],
    ) -> Result<(), CliError> {
        if self.is_sync_unsafe(changes.vault_id)? {
            return Err(self.integrity_error(changes.vault_id)?);
        }

        let validated = match self.validate_checkpoint_chain(changes, checkpoints) {
            Ok(validated) => validated,
            Err(failure) => {
                self.quarantine(checkpoints, &failure)?;
                return Err(CliError::SyncIntegrity {
                    vault_id: failure.vault_id,
                    revision: failure.revision,
                    checkpoint_id: failure.checkpoint_hash,
                });
            }
        };

        let tx = self.connection.transaction()?;
        apply_sync_changes_transaction(&tx, changes)?;
        let commitment = state_commitment_transaction(&tx, changes.vault_id)?;
        if commitment != validated.latest.state_commitment {
            tx.rollback()?;
            let failure = ValidationFailure {
                vault_id: changes.vault_id,
                revision: validated.latest.vault_revision,
                checkpoint_hash: safe_checkpoint_hash(&validated.latest),
                code: "commitment_mismatch",
                conflicting_checkpoint_hash: None,
            };
            self.quarantine(checkpoints, &failure)?;
            return Err(CliError::SyncIntegrity {
                vault_id: failure.vault_id,
                revision: failure.revision,
                checkpoint_id: failure.checkpoint_hash,
            });
        }

        let now = chrono::Utc::now().to_rfc3339();
        for checkpoint in checkpoints {
            let hash = safe_checkpoint_hash(checkpoint);
            record_observed_checkpoint(&tx, checkpoint, &hash, &now)?;
            tx.execute(
                "INSERT OR IGNORE INTO verified_sync_checkpoints
                 (checkpoint_hash, vault_id, revision, checkpoint_json, verified_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    hash,
                    checkpoint.vault_id.to_string(),
                    checkpoint.vault_revision,
                    serde_json::to_string(checkpoint)?,
                    now
                ],
            )?;
        }
        let latest_hash = safe_checkpoint_hash(&validated.latest);
        tx.execute(
            "INSERT INTO verified_checkpoint_heads
             (vault_id, revision, checkpoint_hash, checkpoint_json, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(vault_id) DO UPDATE SET
                revision = excluded.revision,
                checkpoint_hash = excluded.checkpoint_hash,
                checkpoint_json = excluded.checkpoint_json,
                verified_at = excluded.verified_at",
            params![
                changes.vault_id.to_string(),
                validated.latest.vault_revision,
                latest_hash,
                serde_json::to_string(&validated.latest)?,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO sync_integrity_state (vault_id, unsafe, updated_at)
             VALUES (?1, 0, ?2)
             ON CONFLICT(vault_id) DO UPDATE SET updated_at = excluded.updated_at",
            params![changes.vault_id.to_string(), now],
        )?;
        tx.commit()?;
        self.persist()?;
        Ok(())
    }

    pub fn author_checkpoint(
        &mut self,
        changes: &VaultSyncChanges,
        checkpoints: &[SyncCheckpoint],
        author_device_id: uuid::Uuid,
        signing_key: &SigningKey,
    ) -> Result<SyncCheckpoint, CliError> {
        if self.is_sync_unsafe(changes.vault_id)? {
            return Err(self.integrity_error(changes.vault_id)?);
        }

        let previous_checkpoint_hash = match checkpoints.last() {
            Some(checkpoint) => Some(safe_checkpoint_hash(checkpoint)),
            None => self
                .integrity_state(changes.vault_id)?
                .verified_head
                .map(|head| head.checkpoint_hash),
        };
        let state_commitment = self.projected_state_commitment_for_authoring(changes)?;
        let checkpoint = umbra_crypto::checkpoints::sign_checkpoint(
            SyncCheckpoint {
                vault_id: changes.vault_id,
                vault_revision: changes.latest_vault_revision,
                state_commitment,
                previous_checkpoint_hash,
                author_device_id,
                signature: String::new(),
            },
            signing_key,
        )
        .map_err(|_| CliError::Input("failed to encode sync checkpoint"))?;
        let mut chain = checkpoints.to_vec();
        chain.push(checkpoint.clone());
        if let Err(failure) = self.validate_checkpoint_chain(changes, &chain) {
            self.quarantine(checkpoints, &failure)?;
            return Err(CliError::SyncIntegrity {
                vault_id: failure.vault_id,
                revision: failure.revision,
                checkpoint_id: failure.checkpoint_hash,
            });
        }
        Ok(checkpoint)
    }

    fn projected_state_commitment_for_authoring(
        &mut self,
        changes: &VaultSyncChanges,
    ) -> Result<String, CliError> {
        let tx = self.connection.transaction()?;
        apply_sync_changes_transaction(&tx, changes)?;
        let commitment = state_commitment_transaction(&tx, changes.vault_id)?;
        tx.rollback()?;
        Ok(commitment)
    }

    fn validate_checkpoint_chain(
        &self,
        changes: &VaultSyncChanges,
        checkpoints: &[SyncCheckpoint],
    ) -> Result<ValidatedCheckpoints, ValidationFailure> {
        let vault_id = changes.vault_id;
        let fallback_hash = checkpoints
            .last()
            .map(safe_checkpoint_hash)
            .unwrap_or_else(|| "missing".to_owned());
        if self
            .sync_state(vault_id)
            .map_err(|_| {
                ValidationFailure::new(
                    vault_id,
                    changes.latest_vault_revision,
                    fallback_hash.clone(),
                    "local_integrity_state_error",
                )
            })?
            .is_some_and(|state| changes.latest_access_revision < state.latest_access_revision)
        {
            return Err(ValidationFailure::new(
                vault_id,
                changes.latest_vault_revision,
                fallback_hash,
                "access_revision_rollback",
            ));
        }
        if changes.items.iter().any(|item| item.vault_id != vault_id)
            || changes
                .key_wrappings
                .iter()
                .any(|wrapping| wrapping.vault_id != vault_id)
            || changes
                .conflicts
                .iter()
                .any(|conflict| conflict.vault_id != vault_id)
        {
            return Err(ValidationFailure::new(
                vault_id,
                changes.latest_vault_revision,
                fallback_hash,
                "state_scope_mismatch",
            ));
        }
        let head = self
            .integrity_state(vault_id)
            .map_err(|_| {
                ValidationFailure::new(
                    vault_id,
                    changes.latest_vault_revision,
                    fallback_hash.clone(),
                    "local_integrity_state_error",
                )
            })?
            .verified_head;
        if checkpoints.is_empty() {
            if let Some(head) = head
                && head.checkpoint.vault_revision == changes.latest_vault_revision
            {
                return Ok(ValidatedCheckpoints {
                    latest: head.checkpoint,
                });
            }
            return Err(ValidationFailure::new(
                vault_id,
                changes.latest_vault_revision,
                fallback_hash,
                "missing_checkpoint",
            ));
        }

        let mut cursor = head.map(|head| (head.checkpoint.vault_revision, head.checkpoint_hash));
        let mut latest = None;

        for checkpoint in checkpoints {
            let hash = safe_checkpoint_hash(checkpoint);
            if checkpoint.vault_id != vault_id {
                return Err(ValidationFailure::new(
                    vault_id,
                    checkpoint.vault_revision,
                    hash,
                    "vault_mismatch",
                ));
            }

            if let Some(existing_hash) = self
                .observed_checkpoint_hash(vault_id, checkpoint.vault_revision)
                .map_err(|_| {
                    ValidationFailure::new(
                        vault_id,
                        checkpoint.vault_revision,
                        hash.clone(),
                        "local_integrity_state_error",
                    )
                })?
                && existing_hash != hash
            {
                return Err(ValidationFailure {
                    vault_id,
                    revision: checkpoint.vault_revision,
                    checkpoint_hash: hash,
                    code: "equivocation",
                    conflicting_checkpoint_hash: Some(existing_hash),
                });
            }

            let trusted = self
                .trusted_checkpoint_device(checkpoint.author_device_id)
                .map_err(|_| {
                    ValidationFailure::new(
                        vault_id,
                        checkpoint.vault_revision,
                        hash.clone(),
                        "local_integrity_state_error",
                    )
                })?;
            let Some(trusted) = trusted else {
                return Err(ValidationFailure::new(
                    vault_id,
                    checkpoint.vault_revision,
                    hash,
                    "untrusted_signer",
                ));
            };
            if trusted.revoked {
                return Err(ValidationFailure::new(
                    vault_id,
                    checkpoint.vault_revision,
                    hash,
                    "revoked_signer",
                ));
            }
            let key = umbra_auth::verifying_key_from_b64(&trusted.public_key).map_err(|_| {
                ValidationFailure::new(
                    vault_id,
                    checkpoint.vault_revision,
                    hash.clone(),
                    "invalid_trust_anchor",
                )
            })?;
            if umbra_crypto::checkpoints::verify_checkpoint(checkpoint, &key).is_err() {
                return Err(ValidationFailure::new(
                    vault_id,
                    checkpoint.vault_revision,
                    hash,
                    "invalid_signature",
                ));
            }

            match cursor.as_ref() {
                Some((revision, _previous_hash)) if checkpoint.vault_revision < *revision => {
                    let verified_hash = self
                        .verified_checkpoint_hash(vault_id, checkpoint.vault_revision)
                        .map_err(|_| {
                            ValidationFailure::new(
                                vault_id,
                                checkpoint.vault_revision,
                                hash.clone(),
                                "local_integrity_state_error",
                            )
                        })?;
                    if verified_hash.as_ref() == Some(&hash) {
                        continue;
                    }
                    return Err(ValidationFailure::new(
                        vault_id,
                        checkpoint.vault_revision,
                        hash,
                        "non_monotonic_revision",
                    ));
                }
                Some((revision, previous_hash)) if checkpoint.vault_revision == *revision => {
                    if hash != *previous_hash {
                        return Err(ValidationFailure {
                            vault_id,
                            revision: checkpoint.vault_revision,
                            checkpoint_hash: hash,
                            code: "equivocation",
                            conflicting_checkpoint_hash: Some(previous_hash.clone()),
                        });
                    }
                    latest = Some(checkpoint.clone());
                    continue;
                }
                Some((_revision, previous_hash)) => {
                    if checkpoint.previous_checkpoint_hash.as_ref() != Some(previous_hash) {
                        return Err(ValidationFailure::new(
                            vault_id,
                            checkpoint.vault_revision,
                            hash,
                            "missing_predecessor",
                        ));
                    }
                }
                None if checkpoint.previous_checkpoint_hash.is_some() => {
                    return Err(ValidationFailure::new(
                        vault_id,
                        checkpoint.vault_revision,
                        hash,
                        "missing_predecessor",
                    ));
                }
                None => {}
            }
            cursor = Some((checkpoint.vault_revision, hash));
            latest = Some(checkpoint.clone());
        }

        let Some(latest) = latest else {
            let checkpoint = checkpoints
                .last()
                .expect("non-empty checkpoint slice checked above");
            return Err(ValidationFailure::new(
                vault_id,
                checkpoint.vault_revision,
                safe_checkpoint_hash(checkpoint),
                "non_monotonic_revision",
            ));
        };
        if latest.vault_revision != changes.latest_vault_revision {
            return Err(ValidationFailure::new(
                vault_id,
                latest.vault_revision,
                safe_checkpoint_hash(&latest),
                "checkpoint_revision_mismatch",
            ));
        }
        Ok(ValidatedCheckpoints { latest })
    }

    fn trusted_checkpoint_device(
        &self,
        device_id: uuid::Uuid,
    ) -> Result<Option<TrustedCheckpointDevice>, CliError> {
        self.connection
            .query_row(
                "SELECT device_id, public_key, revoked
                 FROM trusted_checkpoint_devices WHERE device_id = ?1",
                params![device_id.to_string()],
                |row| {
                    Ok(TrustedCheckpointDevice {
                        device_id: parse_uuid(row.get::<_, String>(0)?)?,
                        public_key: row.get(1)?,
                        revoked: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(CliError::from)
    }

    fn observed_checkpoint_hash(
        &self,
        vault_id: uuid::Uuid,
        revision: i64,
    ) -> Result<Option<String>, CliError> {
        self.connection
            .query_row(
                "SELECT checkpoint_hash FROM observed_sync_checkpoints
                 WHERE vault_id = ?1 AND revision = ?2
                 ORDER BY checkpoint_hash ASC LIMIT 1",
                params![vault_id.to_string(), revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(CliError::from)
    }

    fn verified_checkpoint_hash(
        &self,
        vault_id: uuid::Uuid,
        revision: i64,
    ) -> Result<Option<String>, CliError> {
        self.connection
            .query_row(
                "SELECT checkpoint_hash FROM verified_sync_checkpoints
                 WHERE vault_id = ?1 AND revision = ?2
                 ORDER BY checkpoint_hash ASC LIMIT 1",
                params![vault_id.to_string(), revision],
                |row| row.get(0),
            )
            .optional()
            .map_err(CliError::from)
    }

    fn quarantine(
        &mut self,
        checkpoints: &[SyncCheckpoint],
        failure: &ValidationFailure,
    ) -> Result<(), CliError> {
        let tx = self.connection.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        for checkpoint in checkpoints {
            if is_safe_signed_checkpoint_metadata(checkpoint) {
                record_observed_checkpoint(
                    &tx,
                    checkpoint,
                    &safe_checkpoint_hash(checkpoint),
                    &now,
                )?;
            }
        }
        tx.execute(
            "INSERT INTO sync_integrity_findings
             (vault_id, revision, checkpoint_hash, code, conflicting_checkpoint_hash, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                failure.vault_id.to_string(),
                failure.revision,
                failure.checkpoint_hash,
                failure.code,
                failure.conflicting_checkpoint_hash,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO sync_integrity_state (vault_id, unsafe, updated_at)
             VALUES (?1, 1, ?2)
             ON CONFLICT(vault_id) DO UPDATE SET unsafe = 1, updated_at = excluded.updated_at",
            params![failure.vault_id.to_string(), now],
        )?;
        tx.commit()?;
        self.persist()?;
        Ok(())
    }

    pub fn integrity_error(&self, vault_id: uuid::Uuid) -> Result<CliError, CliError> {
        let finding = self.integrity_findings(vault_id)?.into_iter().last();
        Ok(CliError::SyncIntegrity {
            vault_id,
            revision: finding.as_ref().map(|value| value.revision).unwrap_or(0),
            checkpoint_id: finding
                .map(|value| value.checkpoint_hash)
                .unwrap_or_else(|| "unknown".to_owned()),
        })
    }

    pub(crate) fn quarantine_transport_failure(
        &mut self,
        vault_id: uuid::Uuid,
        revision: i64,
        checkpoint_id: &str,
        code: &'static str,
    ) -> Result<(), CliError> {
        self.quarantine(
            &[],
            &ValidationFailure::new(vault_id, revision, checkpoint_id.to_owned(), code),
        )
    }

    pub fn delete_item(&self, vault_id: uuid::Uuid, item_id: uuid::Uuid) -> Result<(), CliError> {
        self.connection.execute(
            "DELETE FROM item_revisions WHERE vault_id = ?1 AND item_id = ?2",
            params![vault_id.to_string(), item_id.to_string()],
        )?;
        self.persist()?;
        Ok(())
    }

    pub fn list_item_conflicts(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<CachedItemConflict>, CliError> {
        let mut statement = self.connection.prepare("SELECT conflict_id,vault_id,item_id,base_revision,current_revision,candidate_kind,candidate_envelope_json,author_user_id,state FROM item_conflicts WHERE vault_id = ?1 ORDER BY conflict_id ASC")?;
        let rows =
            statement.query_map(params![vault_id.to_string()], cached_item_conflict_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn item_conflict(
        &self,
        vault_id: uuid::Uuid,
        conflict_id: uuid::Uuid,
    ) -> Result<Option<CachedItemConflict>, CliError> {
        self.connection.query_row("SELECT conflict_id,vault_id,item_id,base_revision,current_revision,candidate_kind,candidate_envelope_json,author_user_id,state FROM item_conflicts WHERE vault_id = ?1 AND conflict_id = ?2", params![vault_id.to_string(), conflict_id.to_string()], cached_item_conflict_from_row).optional().map_err(CliError::from)
    }

    pub fn upsert_item_revision(
        &self,
        item: &umbra_protocol::ItemRevisionResponse,
    ) -> Result<(), CliError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.connection.execute(
            r#"
            INSERT INTO item_revisions (
                vault_id, item_id, revision, vault_revision, key_generation,
                author_user_id, envelope_json, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(vault_id, item_id, revision) DO UPDATE SET
                vault_revision = excluded.vault_revision,
                key_generation = excluded.key_generation,
                author_user_id = excluded.author_user_id,
                envelope_json = excluded.envelope_json,
                updated_at = excluded.updated_at
            "#,
            params![
                item.vault_id.to_string(),
                item.item_id.to_string(),
                item.revision,
                item.vault_revision,
                item.key_generation,
                item.author_user_id.map(|id| id.to_string()),
                serde_json::to_string(&item.envelope)?,
                now
            ],
        )?;
        self.persist()?;
        Ok(())
    }

    pub fn upsert_vault(&self, vault: &umbra_protocol::VaultResponse) -> Result<(), CliError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.connection.execute(
            r#"
            INSERT INTO vaults (
                vault_id, org_id, name, kind, latest_vault_revision, latest_access_revision,
                current_key_generation, needs_key_rotation, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(vault_id) DO UPDATE SET
                org_id = excluded.org_id,
                name = excluded.name,
                kind = excluded.kind,
                latest_vault_revision = excluded.latest_vault_revision,
                latest_access_revision = excluded.latest_access_revision,
                current_key_generation = excluded.current_key_generation,
                needs_key_rotation = excluded.needs_key_rotation,
                updated_at = excluded.updated_at
            "#,
            params![
                vault.vault_id.to_string(),
                vault.org_id.map(|id| id.to_string()),
                vault.name,
                vault_kind_to_str(vault.kind),
                vault.vault_revision,
                vault.access_revision,
                vault.current_key_generation,
                vault.needs_key_rotation,
                now
            ],
        )?;
        self.persist()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn list_vaults(&self) -> Result<Vec<CachedVault>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id, name, kind, latest_vault_revision, latest_access_revision,
                   current_key_generation, needs_key_rotation
            FROM vaults
            ORDER BY name ASC, vault_id ASC
            "#,
        )?;
        let rows = statement.query_map([], cached_vault_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn find_vaults_by_name(&self, name: &str) -> Result<Vec<CachedVault>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id, name, kind, latest_vault_revision, latest_access_revision,
                   current_key_generation, needs_key_rotation
            FROM vaults
            WHERE name = ?1
            ORDER BY vault_id ASC
            "#,
        )?;
        let rows = statement.query_map(params![name], cached_vault_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn cached_vault_ids(&self) -> Result<Vec<uuid::Uuid>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id
            FROM vaults
            ORDER BY name ASC, vault_id ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| parse_uuid(row.get::<_, String>(0)?))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    #[allow(dead_code)]
    pub fn sync_state(&self, vault_id: uuid::Uuid) -> Result<Option<CachedSyncState>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id, latest_vault_revision, latest_access_revision, synced_at
            FROM sync_state
            WHERE vault_id = ?1
            "#,
        )?;
        let result = statement.query_row(params![vault_id.to_string()], cached_sync_state_from_row);
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(CliError::from(error)),
        }
    }

    #[allow(dead_code)]
    pub fn upsert_sync_state(
        &self,
        vault_id: uuid::Uuid,
        latest_vault_revision: i64,
        latest_access_revision: i64,
    ) -> Result<(), CliError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.connection.execute(
            r#"
            INSERT INTO sync_state (
                vault_id, latest_vault_revision, latest_access_revision, synced_at
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(vault_id) DO UPDATE SET
                latest_vault_revision = excluded.latest_vault_revision,
                latest_access_revision = excluded.latest_access_revision,
                synced_at = excluded.synced_at
            "#,
            params![
                vault_id.to_string(),
                latest_vault_revision,
                latest_access_revision,
                now
            ],
        )?;
        self.persist()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn list_item_revisions(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<CachedItemRevision>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id, item_id, revision, vault_revision, key_generation,
                   author_user_id, envelope_json
            FROM item_revisions
            WHERE vault_id = ?1
            ORDER BY vault_revision ASC, item_id ASC, revision ASC
            "#,
        )?;
        let rows =
            statement.query_map(params![vault_id.to_string()], cached_item_revision_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    #[allow(dead_code)]
    pub fn list_key_wrappings(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<CachedKeyWrapping>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT id, vault_id, user_id, device_id, wrapping_type, envelope_json, key_generation
            FROM vault_key_wrappings
            WHERE vault_id = ?1
            ORDER BY key_generation ASC, id ASC
            "#,
        )?;
        let rows =
            statement.query_map(params![vault_id.to_string()], cached_key_wrapping_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    #[allow(dead_code)]
    pub fn latest_key_wrapping(
        &self,
        vault_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Result<Option<CachedKeyWrapping>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT id, vault_id, user_id, device_id, wrapping_type, envelope_json, key_generation
            FROM vault_key_wrappings
            WHERE vault_id = ?1 AND user_id = ?2
            ORDER BY key_generation DESC
            LIMIT 1
            "#,
        )?;
        let result = statement.query_row(
            params![vault_id.to_string(), user_id.to_string()],
            cached_key_wrapping_from_row,
        );
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(CliError::from(error)),
        }
    }

    pub fn latest_device_key_wrapping(
        &self,
        vault_id: uuid::Uuid,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
    ) -> Result<Option<CachedKeyWrapping>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT id, vault_id, user_id, device_id, wrapping_type, envelope_json, key_generation
            FROM vault_key_wrappings
            WHERE vault_id = ?1 AND user_id = ?2 AND device_id = ?3
              AND wrapping_type = 'device_public_key'
            ORDER BY key_generation DESC
            LIMIT 1
            "#,
        )?;
        let result = statement.query_row(
            params![
                vault_id.to_string(),
                user_id.to_string(),
                device_id.to_string()
            ],
            cached_key_wrapping_from_row,
        );
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(CliError::from(error)),
        }
    }

    pub fn list_latest_item_revisions(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<CachedItemRevision>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT ir.vault_id, ir.item_id, ir.revision, ir.vault_revision, ir.key_generation,
                   ir.author_user_id, ir.envelope_json
            FROM item_revisions ir
            INNER JOIN (
                SELECT vault_id, item_id, MAX(revision) AS max_revision
                FROM item_revisions
                WHERE vault_id = ?1
                GROUP BY vault_id, item_id
            ) latest
              ON latest.vault_id = ir.vault_id
             AND latest.item_id = ir.item_id
             AND latest.max_revision = ir.revision
            WHERE ir.vault_id = ?1
            ORDER BY ir.vault_revision ASC, ir.item_id ASC
            "#,
        )?;
        let rows =
            statement.query_map(params![vault_id.to_string()], cached_item_revision_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn latest_item_revision(
        &self,
        vault_id: uuid::Uuid,
        item_id: uuid::Uuid,
    ) -> Result<Option<CachedItemRevision>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id, item_id, revision, vault_revision, key_generation,
                   author_user_id, envelope_json
            FROM item_revisions
            WHERE vault_id = ?1 AND item_id = ?2
            ORDER BY revision DESC
            LIMIT 1
            "#,
        )?;
        let result = statement.query_row(
            params![vault_id.to_string(), item_id.to_string()],
            cached_item_revision_from_row,
        );
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(CliError::from(error)),
        }
    }

    pub fn status(&self) -> Result<CacheStatus, CliError> {
        Ok(CacheStatus {
            profile: self.profile.clone(),
            synced_vault_count: self.count_table("sync_state")?,
            item_revision_count: self.count_table("item_revisions")?,
            key_wrapping_count: self.count_table("vault_key_wrappings")?,
            sync_state_count: self.count_table("sync_state")?,
        })
    }

    fn count_table(&self, table: &str) -> Result<i64, CliError> {
        let sql = match table {
            "item_revisions" => "SELECT COUNT(*) FROM item_revisions",
            "vault_key_wrappings" => "SELECT COUNT(*) FROM vault_key_wrappings",
            "sync_state" => "SELECT COUNT(*) FROM sync_state",
            _ => return Err(CliError::Input("unknown cache table")),
        };
        Ok(self.connection.query_row(sql, [], |row| row.get(0))?)
    }

    pub fn clear_persistent(profile: &str) -> Result<(), CliError> {
        let path = profile_cache_dir(profile).join("cache.enc");
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        KeyringCacheKeyStore.clear(profile)
    }

    fn persist(&self) -> Result<(), CliError> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&persistence.lock_path)?;
        lock.lock_exclusive()?;
        let current_hash = snapshot_hash(&persistence.encrypted_path)?;
        if current_hash != *persistence.expected_snapshot_hash.borrow() {
            return Err(CliError::Input(
                "local cache changed by another process; rerun the command",
            ));
        }
        let existing_key = persistence.key_store.get(&self.profile)?;
        let key = existing_key
            .clone()
            .unwrap_or_else(LocalUnlockKey::generate);
        if existing_key.is_none() {
            persistence.key_store.set(&self.profile, &key)?;
        }
        let snapshot = self.connection.serialize(DatabaseName::Main)?;
        let envelope = encrypt_local_unlock_state(&key, cache_aad(&self.profile), &snapshot)?;
        let bytes = serde_json::to_vec(&PersistedCacheV1 {
            version: CACHE_FORMAT_VERSION,
            envelope,
        })?;
        write_atomic(&persistence.encrypted_path, &bytes)?;
        *persistence.expected_snapshot_hash.borrow_mut() = Some(snapshot_bytes_hash(&bytes));
        Ok(())
    }

    fn create_schema(&self) -> Result<(), CliError> {
        self.connection.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                org_id TEXT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                latest_vault_revision INTEGER NOT NULL DEFAULT 0,
                latest_access_revision INTEGER NOT NULL DEFAULT 0,
                current_key_generation INTEGER NOT NULL DEFAULT 1,
                needs_key_rotation INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                vault_id TEXT PRIMARY KEY,
                latest_vault_revision INTEGER NOT NULL DEFAULT 0,
                latest_access_revision INTEGER NOT NULL DEFAULT 0,
                synced_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_key_wrappings (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                device_id TEXT,
                wrapping_type TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                key_generation INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_key_wrapping_metadata (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                device_id TEXT,
                wrapping_type TEXT NOT NULL,
                key_generation INTEGER NOT NULL,
                envelope_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS item_revisions (
                vault_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                vault_revision INTEGER NOT NULL,
                key_generation INTEGER NOT NULL,
                author_user_id TEXT,
                envelope_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (vault_id, item_id, revision)
            );

            CREATE TABLE IF NOT EXISTS item_conflicts (
                conflict_id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                base_revision INTEGER NOT NULL,
                current_revision INTEGER NOT NULL,
                candidate_kind TEXT NOT NULL,
                candidate_envelope_json TEXT,
                author_user_id TEXT,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS deleted_item_tombstones (
                vault_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                deleted_at_revision INTEGER NOT NULL,
                PRIMARY KEY (vault_id, item_id)
            );

            CREATE TABLE IF NOT EXISTS trusted_checkpoint_devices (
                device_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                trusted_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS observed_sync_checkpoints (
                checkpoint_hash TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                checkpoint_json TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_observed_sync_checkpoints_vault_revision
                ON observed_sync_checkpoints (vault_id, revision);

            CREATE TABLE IF NOT EXISTS verified_sync_checkpoints (
                checkpoint_hash TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                checkpoint_json TEXT NOT NULL,
                verified_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_verified_sync_checkpoints_vault_revision
                ON verified_sync_checkpoints (vault_id, revision);

            CREATE TABLE IF NOT EXISTS verified_checkpoint_heads (
                vault_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                checkpoint_hash TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                verified_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_integrity_state (
                vault_id TEXT PRIMARY KEY,
                unsafe INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_integrity_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                checkpoint_hash TEXT NOT NULL,
                code TEXT NOT NULL,
                conflicting_checkpoint_hash TEXT,
                observed_at TEXT NOT NULL
            );
            "#,
        )?;
        self.add_column_if_missing(
            "vaults",
            "latest_access_revision",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        self.add_column_if_missing(
            "sync_state",
            "latest_access_revision",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        self.add_column_if_missing(
            "sync_integrity_findings",
            "conflicting_checkpoint_hash",
            "TEXT",
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('schema_version', '1')",
            params![],
        )?;
        Ok(())
    }

    fn add_column_if_missing(
        &self,
        table: &str,
        column: &str,
        definition: &str,
    ) -> Result<(), CliError> {
        match (table, column, definition) {
            ("vaults", "latest_access_revision", "INTEGER NOT NULL DEFAULT 0")
            | ("sync_state", "latest_access_revision", "INTEGER NOT NULL DEFAULT 0")
            | ("sync_integrity_findings", "conflicting_checkpoint_hash", "TEXT") => {}
            _ => return Err(CliError::Input("unknown cache migration column")),
        }

        let pragma = format!("PRAGMA table_info({table})");
        let mut statement = self.connection.prepare(&pragma)?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if !columns.iter().any(|existing| existing == column) {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
            self.connection.execute(&sql, [])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ValidationFailure {
    vault_id: uuid::Uuid,
    revision: i64,
    checkpoint_hash: String,
    code: &'static str,
    conflicting_checkpoint_hash: Option<String>,
}

impl ValidationFailure {
    fn new(
        vault_id: uuid::Uuid,
        revision: i64,
        checkpoint_hash: String,
        code: &'static str,
    ) -> Self {
        Self {
            vault_id,
            revision,
            checkpoint_hash,
            code,
            conflicting_checkpoint_hash: None,
        }
    }
}

struct ValidatedCheckpoints {
    latest: SyncCheckpoint,
}

fn apply_sync_changes_transaction(
    tx: &rusqlite::Transaction<'_>,
    changes: &VaultSyncChanges,
) -> Result<(), CliError> {
    let now = chrono::Utc::now().to_rfc3339();
    tx.execute(
        r#"
        INSERT INTO sync_state (
            vault_id, latest_vault_revision, latest_access_revision, synced_at
        )
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(vault_id) DO UPDATE SET
            latest_vault_revision = excluded.latest_vault_revision,
            latest_access_revision = excluded.latest_access_revision,
            synced_at = excluded.synced_at
        "#,
        params![
            changes.vault_id.to_string(),
            changes.latest_vault_revision,
            changes.latest_access_revision,
            now
        ],
    )?;

    for item in &changes.items {
        tx.execute(
            r#"
            INSERT INTO item_revisions (
                vault_id, item_id, revision, vault_revision, key_generation,
                author_user_id, envelope_json, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(vault_id, item_id, revision) DO UPDATE SET
                vault_revision = excluded.vault_revision,
                key_generation = excluded.key_generation,
                author_user_id = excluded.author_user_id,
                envelope_json = excluded.envelope_json,
                updated_at = excluded.updated_at
            "#,
            params![
                item.vault_id.to_string(),
                item.item_id.to_string(),
                item.revision,
                item.vault_revision,
                item.key_generation,
                item.author_user_id.map(|id| id.to_string()),
                serde_json::to_string(&item.envelope)?,
                now
            ],
        )?;
        tx.execute(
            "DELETE FROM deleted_item_tombstones WHERE vault_id = ?1 AND item_id = ?2",
            params![changes.vault_id.to_string(), item.item_id.to_string()],
        )?;
    }

    for item_id in &changes.deleted_items {
        tx.execute(
            "DELETE FROM item_revisions WHERE vault_id = ?1 AND item_id = ?2",
            params![changes.vault_id.to_string(), item_id.to_string()],
        )?;
        tx.execute(
            "INSERT INTO deleted_item_tombstones (vault_id, item_id, deleted_at_revision)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(vault_id, item_id) DO UPDATE SET
                deleted_at_revision = excluded.deleted_at_revision",
            params![
                changes.vault_id.to_string(),
                item_id.to_string(),
                changes.latest_vault_revision
            ],
        )?;
    }

    let active_wrapping_ids = changes
        .key_wrappings
        .iter()
        .map(|wrapping| wrapping.id.to_string())
        .collect::<Vec<_>>();
    if active_wrapping_ids.is_empty() {
        tx.execute(
            "DELETE FROM vault_key_wrappings WHERE vault_id = ?1",
            params![changes.vault_id.to_string()],
        )?;
    } else {
        let placeholders = (0..active_wrapping_ids.len())
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "DELETE FROM vault_key_wrappings WHERE vault_id = ? AND id NOT IN ({placeholders})"
        );
        let mut values = Vec::with_capacity(active_wrapping_ids.len() + 1);
        values.push(changes.vault_id.to_string());
        values.extend(active_wrapping_ids);
        tx.execute(&sql, params_from_iter(values))?;
    }

    for wrapping in &changes.key_wrappings {
        tx.execute(
            r#"
            INSERT INTO vault_key_wrappings (
                id, vault_id, user_id, device_id, wrapping_type,
                envelope_json, key_generation, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(id) DO UPDATE SET
                vault_id = excluded.vault_id,
                user_id = excluded.user_id,
                device_id = excluded.device_id,
                wrapping_type = excluded.wrapping_type,
                envelope_json = excluded.envelope_json,
                key_generation = excluded.key_generation,
                updated_at = excluded.updated_at
            "#,
            params![
                wrapping.id.to_string(),
                wrapping.vault_id.to_string(),
                wrapping.user_id.to_string(),
                wrapping.device_id.map(|id| id.to_string()),
                wrapping.wrapping_type.as_str(),
                serde_json::to_string(&wrapping.envelope)?,
                wrapping.key_generation,
                now
            ],
        )?;
    }

    // v3 carries a complete, ciphertext-free view for the commitment. Older
    // responses retain their existing behavior by deriving that view locally.
    let key_wrapping_metadata = if changes.key_wrapping_metadata.is_empty() {
        changes
            .key_wrappings
            .iter()
            .map(|wrapping| {
                Ok(VaultKeyWrappingMetadata {
                    id: wrapping.id,
                    vault_id: wrapping.vault_id,
                    user_id: wrapping.user_id,
                    device_id: wrapping.device_id,
                    wrapping_type: wrapping.wrapping_type.clone(),
                    key_generation: wrapping.key_generation,
                    envelope_hash: hash_json(&wrapping.envelope)?,
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?
    } else {
        changes.key_wrapping_metadata.clone()
    };
    let active_metadata_ids = key_wrapping_metadata
        .iter()
        .map(|metadata| metadata.id.to_string())
        .collect::<Vec<_>>();
    if active_metadata_ids.is_empty() {
        tx.execute(
            "DELETE FROM vault_key_wrapping_metadata WHERE vault_id = ?1",
            params![changes.vault_id.to_string()],
        )?;
    } else {
        let placeholders = (0..active_metadata_ids.len())
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "DELETE FROM vault_key_wrapping_metadata WHERE vault_id = ? AND id NOT IN ({placeholders})"
        );
        let mut values = Vec::with_capacity(active_metadata_ids.len() + 1);
        values.push(changes.vault_id.to_string());
        values.extend(active_metadata_ids);
        tx.execute(&sql, params_from_iter(values))?;
    }
    for metadata in key_wrapping_metadata {
        tx.execute(
            r#"
            INSERT INTO vault_key_wrapping_metadata (
                id, vault_id, user_id, device_id, wrapping_type,
                key_generation, envelope_hash, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(id) DO UPDATE SET
                vault_id = excluded.vault_id,
                user_id = excluded.user_id,
                device_id = excluded.device_id,
                wrapping_type = excluded.wrapping_type,
                key_generation = excluded.key_generation,
                envelope_hash = excluded.envelope_hash,
                updated_at = excluded.updated_at
            "#,
            params![
                metadata.id.to_string(),
                metadata.vault_id.to_string(),
                metadata.user_id.to_string(),
                metadata.device_id.map(|id| id.to_string()),
                metadata.wrapping_type,
                metadata.key_generation,
                metadata.envelope_hash,
                now,
            ],
        )?;
    }

    tx.execute(
        "DELETE FROM item_conflicts WHERE vault_id = ?1",
        params![changes.vault_id.to_string()],
    )?;
    for conflict in &changes.conflicts {
        tx.execute(
            "INSERT INTO item_conflicts
             (conflict_id,vault_id,item_id,base_revision,current_revision,candidate_kind,
              candidate_envelope_json,author_user_id,state,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                conflict.conflict_id.to_string(),
                conflict.vault_id.to_string(),
                conflict.item_id.to_string(),
                conflict.base_revision,
                conflict.current_revision,
                conflict.candidate_kind,
                conflict
                    .candidate_envelope
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                conflict.author_user_id.map(|id| id.to_string()),
                conflict.state,
                now,
            ],
        )?;
    }
    Ok(())
}

fn state_commitment_transaction(
    tx: &rusqlite::Transaction<'_>,
    vault_id: uuid::Uuid,
) -> Result<String, CliError> {
    let mut entries = Vec::new();
    let mut items = tx.prepare(
        r#"
        SELECT ir.item_id, ir.revision, ir.vault_revision, ir.key_generation,
               ir.author_user_id, ir.envelope_json
        FROM item_revisions ir
        INNER JOIN (
            SELECT vault_id, item_id, MAX(revision) AS max_revision
            FROM item_revisions WHERE vault_id = ?1 GROUP BY vault_id, item_id
        ) latest
          ON latest.vault_id = ir.vault_id
         AND latest.item_id = ir.item_id
         AND latest.max_revision = ir.revision
        WHERE ir.vault_id = ?1
        ORDER BY ir.item_id ASC
        "#,
    )?;
    let item_rows = items.query_map(params![vault_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    for row in item_rows {
        let (item_id, revision, vault_revision, key_generation, author_user_id, envelope) = row?;
        let envelope: serde_json::Value = serde_json::from_str(&envelope)?;
        entries.push(serde_json::to_vec(&serde_json::json!([
            "item",
            vault_id,
            item_id,
            revision,
            vault_revision,
            key_generation,
            author_user_id,
            hash_json(&envelope)?
        ]))?);
    }

    let mut tombstones = tx.prepare(
        "SELECT item_id, deleted_at_revision FROM deleted_item_tombstones
         WHERE vault_id = ?1 ORDER BY item_id ASC",
    )?;
    let tombstone_rows = tombstones.query_map(params![vault_id.to_string()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in tombstone_rows {
        let (item_id, revision) = row?;
        entries.push(serde_json::to_vec(&serde_json::json!([
            "deleted", vault_id, item_id, revision
        ]))?);
    }

    let mut conflicts = tx.prepare(
        "SELECT conflict_id,item_id,base_revision,current_revision,candidate_kind,
                candidate_envelope_json,author_user_id,state
         FROM item_conflicts WHERE vault_id = ?1 ORDER BY conflict_id ASC",
    )?;
    let conflict_rows = conflicts.query_map(params![vault_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;
    for row in conflict_rows {
        let (
            conflict_id,
            item_id,
            base_revision,
            current_revision,
            candidate_kind,
            candidate_envelope,
            author_user_id,
            state,
        ) = row?;
        let candidate_hash = candidate_envelope
            .map(|value| serde_json::from_str::<serde_json::Value>(&value))
            .transpose()?
            .as_ref()
            .map(hash_json)
            .transpose()?;
        entries.push(serde_json::to_vec(&serde_json::json!([
            "conflict",
            vault_id,
            conflict_id,
            item_id,
            base_revision,
            current_revision,
            candidate_kind,
            candidate_hash,
            author_user_id,
            state
        ]))?);
    }

    // Key envelopes are ciphertext, but their routing metadata is security
    // relevant: omitting an envelope or substituting its recipient must change
    // the signed checkpoint just like changing an item ciphertext does.
    let mut wrappings = tx.prepare(
        "SELECT id, user_id, device_id, wrapping_type, key_generation, envelope_hash
         FROM vault_key_wrapping_metadata WHERE vault_id = ?1
         ORDER BY key_generation ASC, user_id ASC, device_id ASC, id ASC",
    )?;
    let wrapping_rows = wrappings.query_map(params![vault_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    for row in wrapping_rows {
        let (id, user_id, device_id, wrapping_type, key_generation, envelope_hash) = row?;
        entries.push(serde_json::to_vec(&serde_json::json!([
            "key_wrapping",
            vault_id,
            id,
            user_id,
            device_id,
            wrapping_type,
            key_generation,
            envelope_hash
        ]))?);
    }
    Ok(umbra_crypto::checkpoints::state_commitment(entries))
}

fn hash_json(value: &serde_json::Value) -> Result<String, CliError> {
    Ok(Base64UrlUnpadded::encode_string(&Sha256::digest(
        canonical_json_bytes(value)?,
    )))
}

fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, CliError> {
    fn write(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<(), serde_json::Error> {
        match value {
            serde_json::Value::Object(map) => {
                output.push(b'{');
                let mut keys = map.keys().collect::<Vec<_>>();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                    output.push(b':');
                    write(&map[key], output)?;
                }
                output.push(b'}');
            }
            serde_json::Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(value, output)?;
                }
                output.push(b']');
            }
            _ => output.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        }
        Ok(())
    }

    let mut output = Vec::new();
    write(value, &mut output)?;
    Ok(output)
}

fn record_observed_checkpoint(
    tx: &rusqlite::Transaction<'_>,
    checkpoint: &SyncCheckpoint,
    checkpoint_hash: &str,
    observed_at: &str,
) -> Result<(), CliError> {
    tx.execute(
        "INSERT OR IGNORE INTO observed_sync_checkpoints
         (checkpoint_hash, vault_id, revision, checkpoint_json, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            checkpoint_hash,
            checkpoint.vault_id.to_string(),
            checkpoint.vault_revision,
            serde_json::to_string(checkpoint)?,
            observed_at
        ],
    )?;
    Ok(())
}

fn safe_checkpoint_hash(checkpoint: &SyncCheckpoint) -> String {
    umbra_crypto::checkpoints::checkpoint_hash(checkpoint).unwrap_or_else(|_| {
        let encoded = serde_json::to_vec(checkpoint).unwrap_or_default();
        Base64UrlUnpadded::encode_string(&Sha256::digest(encoded))
    })
}

fn is_safe_signed_checkpoint_metadata(checkpoint: &SyncCheckpoint) -> bool {
    let commitment_is_safe = Base64UrlUnpadded::decode_vec(&checkpoint.state_commitment)
        .is_ok_and(|bytes| bytes.len() == 32);
    let predecessor_is_safe = checkpoint
        .previous_checkpoint_hash
        .as_deref()
        .map(Base64UrlUnpadded::decode_vec)
        .transpose()
        .is_ok_and(|value| value.is_none_or(|bytes| bytes.len() == 32));
    let signature_is_safe =
        Base64UrlUnpadded::decode_vec(&checkpoint.signature).is_ok_and(|bytes| bytes.len() == 64);
    commitment_is_safe && predecessor_is_safe && signature_is_safe
}

fn verified_checkpoint_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<VerifiedCheckpoint, rusqlite::Error> {
    Ok(VerifiedCheckpoint {
        checkpoint_hash: row.get(0)?,
        checkpoint: parse_json_as(row.get::<_, String>(1)?)?,
        verified_at: row.get(2)?,
    })
}

fn parse_json_as<T: serde::de::DeserializeOwned>(value: String) -> Result<T, rusqlite::Error> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

pub fn profile_cache_dir(profile: &str) -> PathBuf {
    profile_cache_dir_from_base(&local_data_dir(), profile)
}

pub fn profile_cache_dir_from_base(base: &Path, profile: &str) -> PathBuf {
    base.join("profiles").join(sanitize_profile_name(profile))
}

fn local_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("UMBRA_CACHE_DIR") {
        return PathBuf::from(path);
    }

    let base = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
    } else {
        None
    }
    .or_else(|| std::env::var("XDG_DATA_HOME").ok().map(PathBuf::from))
    .or_else(|| {
        std::env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".local").join("share"))
    })
    .unwrap_or_else(|| PathBuf::from("."));
    base.join("umbra")
}

fn sanitize_profile_name(profile: &str) -> String {
    profile
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn cache_keyring_account(profile: &str) -> String {
    format!(
        "cache:v1:{}",
        Base64UrlUnpadded::encode_string(profile.as_bytes())
    )
}

fn cache_aad(profile: &str) -> AadV1 {
    AadV1 {
        app: "umbra".to_owned(),
        purpose: "local_cache".to_owned(),
        schema: CACHE_FORMAT_VERSION,
        vault_id: profile.to_owned(),
        item_id: Some("sqlite-snapshot".to_owned()),
        revision: None,
        kind: None,
    }
}

fn deserialize_database(connection: &mut Connection, bytes: Vec<u8>) -> Result<(), CliError> {
    use std::ptr::{NonNull, copy_nonoverlapping};

    let length = bytes.len();
    let raw = unsafe { rusqlite::ffi::sqlite3_malloc(length as i32) }.cast::<u8>();
    let pointer = NonNull::new(raw)
        .ok_or_else(|| std::io::Error::other("unable to allocate SQLite cache snapshot"))?;
    unsafe { copy_nonoverlapping(bytes.as_ptr(), pointer.as_ptr(), length) };
    let data = unsafe { rusqlite::serialize::OwnedData::from_raw_nonnull(pointer, length) };
    connection.deserialize(DatabaseName::Main, data, false)?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().ok_or(CliError::Input(
        "encrypted cache path has no parent directory",
    ))?;
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("cache.enc");
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&temporary, bytes)?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn snapshot_hash(path: &Path) -> Result<Option<[u8; 32]>, CliError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(snapshot_bytes_hash(&bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn snapshot_bytes_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn cached_vault_from_row(row: &rusqlite::Row<'_>) -> Result<CachedVault, rusqlite::Error> {
    Ok(CachedVault {
        vault_id: parse_uuid(row.get::<_, String>(0)?)?,
        name: row.get(1)?,
        kind: row.get(2)?,
        latest_vault_revision: row.get(3)?,
        latest_access_revision: row.get(4)?,
        current_key_generation: row.get(5)?,
        needs_key_rotation: row.get(6)?,
    })
}

fn cached_sync_state_from_row(row: &rusqlite::Row<'_>) -> Result<CachedSyncState, rusqlite::Error> {
    Ok(CachedSyncState {
        vault_id: parse_uuid(row.get::<_, String>(0)?)?,
        latest_vault_revision: row.get(1)?,
        latest_access_revision: row.get(2)?,
        synced_at: row.get(3)?,
    })
}

fn cached_item_revision_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<CachedItemRevision, rusqlite::Error> {
    let author_user_id: Option<String> = row.get(5)?;
    let envelope_json: String = row.get(6)?;
    Ok(CachedItemRevision {
        vault_id: parse_uuid(row.get::<_, String>(0)?)?,
        item_id: parse_uuid(row.get::<_, String>(1)?)?,
        revision: row.get(2)?,
        vault_revision: row.get(3)?,
        key_generation: row.get(4)?,
        author_user_id: author_user_id.map(parse_uuid).transpose()?,
        envelope: parse_json(envelope_json)?,
    })
}

fn cached_item_conflict_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<CachedItemConflict, rusqlite::Error> {
    let candidate_envelope_json: Option<String> = row.get(6)?;
    let author_user_id: Option<String> = row.get(7)?;
    Ok(CachedItemConflict {
        conflict_id: parse_uuid(row.get::<_, String>(0)?)?,
        vault_id: parse_uuid(row.get::<_, String>(1)?)?,
        item_id: parse_uuid(row.get::<_, String>(2)?)?,
        base_revision: row.get(3)?,
        current_revision: row.get(4)?,
        candidate_kind: row.get(5)?,
        candidate_envelope: candidate_envelope_json
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        author_user_id: author_user_id.map(parse_uuid).transpose()?,
        state: row.get(8)?,
    })
}

#[allow(dead_code)]
fn cached_key_wrapping_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<CachedKeyWrapping, rusqlite::Error> {
    let device_id: Option<String> = row.get(3)?;
    let envelope_json: String = row.get(5)?;
    Ok(CachedKeyWrapping {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        vault_id: parse_uuid(row.get::<_, String>(1)?)?,
        user_id: parse_uuid(row.get::<_, String>(2)?)?,
        device_id: device_id.map(parse_uuid).transpose()?,
        wrapping_type: row.get(4)?,
        envelope: parse_json(envelope_json)?,
        key_generation: row.get(6)?,
    })
}

fn parse_uuid(value: String) -> Result<uuid::Uuid, rusqlite::Error> {
    uuid::Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_json(value: String) -> Result<serde_json::Value, rusqlite::Error> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn vault_kind_to_str(kind: VaultKind) -> &'static str {
    match kind {
        VaultKind::Personal => "personal",
        VaultKind::Shared => "shared",
        VaultKind::Project => "project",
        VaultKind::Org => "org",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryCacheKeyStore(Mutex<HashMap<String, LocalUnlockKey>>);

    impl CacheKeyStore for MemoryCacheKeyStore {
        fn get(&self, profile: &str) -> Result<Option<LocalUnlockKey>, CliError> {
            Ok(self.0.lock().unwrap().get(profile).cloned())
        }

        fn set(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError> {
            self.0
                .lock()
                .unwrap()
                .insert(profile.to_owned(), key.clone());
            Ok(())
        }

        fn clear(&self, profile: &str) -> Result<(), CliError> {
            self.0.lock().unwrap().remove(profile);
            Ok(())
        }
    }

    struct KeyBeforeSnapshotStore {
        artifact_path: PathBuf,
        key: Mutex<Option<LocalUnlockKey>>,
    }

    impl CacheKeyStore for KeyBeforeSnapshotStore {
        fn get(&self, _profile: &str) -> Result<Option<LocalUnlockKey>, CliError> {
            Ok(self.key.lock().unwrap().clone())
        }

        fn set(&self, _profile: &str, key: &LocalUnlockKey) -> Result<(), CliError> {
            if self.artifact_path.exists() {
                return Err(CliError::Input("cache snapshot was written before its key"));
            }
            *self.key.lock().unwrap() = Some(key.clone());
            Ok(())
        }

        fn clear(&self, _profile: &str) -> Result<(), CliError> {
            *self.key.lock().unwrap() = None;
            Ok(())
        }
    }

    fn persisted_cache(
        profile: &str,
        root: &tempfile::TempDir,
        keys: Arc<MemoryCacheKeyStore>,
    ) -> LocalCache {
        LocalCache::open_path_with_key_store(profile, root.path().join("cache.db"), keys).unwrap()
    }

    #[test]
    fn persisted_cache_reopens_without_plaintext_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let keys = Arc::new(MemoryCacheKeyStore::default());
        let cache = persisted_cache("personal", &root, keys.clone());
        cache
            .upsert_vault(&umbra_protocol::VaultResponse {
                vault_id: uuid::Uuid::new_v4(),
                org_id: None,
                name: "fixture-plaintext".to_owned(),
                kind: VaultKind::Personal,
                vault_revision: 1,
                access_revision: 1,
                current_key_generation: 1,
                needs_key_rotation: false,
            })
            .unwrap();
        let artifact = root.path().join("cache.enc");
        let bytes = std::fs::read(&artifact).unwrap();
        assert!(
            !bytes
                .windows(b"fixture-plaintext".len())
                .any(|part| part == b"fixture-plaintext")
        );
        assert!(
            !bytes
                .windows(b"SQLite format 3".len())
                .any(|part| part == b"SQLite format 3")
        );
        assert_eq!(
            persisted_cache("personal", &root, keys)
                .list_vaults()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn first_snapshot_stores_cache_key_before_writing_artifact() {
        let root = tempfile::tempdir().unwrap();
        let artifact = root.path().join("cache.enc");
        let keys = Arc::new(KeyBeforeSnapshotStore {
            artifact_path: artifact.clone(),
            key: Mutex::new(None),
        });
        let cache = LocalCache::open_path_with_key_store(
            "personal",
            root.path().join("cache.db"),
            keys.clone(),
        )
        .unwrap();

        cache
            .upsert_vault(&umbra_protocol::VaultResponse {
                vault_id: uuid::Uuid::new_v4(),
                org_id: None,
                name: "first-snapshot".to_owned(),
                kind: VaultKind::Personal,
                vault_revision: 1,
                access_revision: 1,
                current_key_generation: 1,
                needs_key_rotation: false,
            })
            .unwrap();

        assert!(keys.get("personal").unwrap().is_some());
        assert!(artifact.exists());
    }

    #[test]
    fn trusted_checkpoint_anchor_survives_persistent_cache_reopen() {
        let root = tempfile::tempdir().unwrap();
        let keys = Arc::new(MemoryCacheKeyStore::default());
        let device = TrustedCheckpointDevice {
            device_id: uuid::Uuid::new_v4(),
            public_key: Base64UrlUnpadded::encode_string(&[9u8; 32]),
            revoked: false,
        };
        persisted_cache("personal", &root, keys.clone())
            .record_trusted_checkpoint_device(&device)
            .unwrap();

        assert_eq!(
            persisted_cache("personal", &root, keys)
                .trusted_checkpoint_devices()
                .unwrap(),
            vec![device]
        );
    }

    #[test]
    fn checkpoint_quarantine_survives_persistent_cache_reopen() {
        let root = tempfile::tempdir().unwrap();
        let keys = Arc::new(MemoryCacheKeyStore::default());
        let vault_id = uuid::Uuid::new_v4();
        let mut cache = persisted_cache("personal", &root, keys.clone());
        cache
            .quarantine_transport_failure(vault_id, 7, "invalid-checkpoint", "invalid_signature")
            .unwrap();
        drop(cache);

        assert!(
            persisted_cache("personal", &root, keys)
                .is_sync_unsafe(vault_id)
                .unwrap()
        );
    }

    #[test]
    fn stale_writer_cannot_overwrite_persisted_quarantine() {
        let root = tempfile::tempdir().unwrap();
        let keys = Arc::new(MemoryCacheKeyStore::default());
        let vault_id = uuid::Uuid::new_v4();
        let stale_cache = persisted_cache("personal", &root, keys.clone());
        let mut detecting_cache = persisted_cache("personal", &root, keys.clone());

        detecting_cache
            .quarantine_transport_failure(vault_id, 7, "invalid-checkpoint", "invalid_signature")
            .unwrap();
        let result = stale_cache.record_trusted_checkpoint_device(&TrustedCheckpointDevice {
            device_id: uuid::Uuid::new_v4(),
            public_key: Base64UrlUnpadded::encode_string(&[3u8; 32]),
            revoked: false,
        });

        assert!(result.is_err());
        assert!(
            persisted_cache("personal", &root, keys)
                .is_sync_unsafe(vault_id)
                .unwrap()
        );
    }

    #[test]
    fn legacy_cache_is_left_untouched_and_refused() {
        let root = tempfile::tempdir().unwrap();
        let legacy = root.path().join("cache.db");
        std::fs::write(&legacy, b"legacy-cache-fixture").unwrap();
        let before = std::fs::read(&legacy).unwrap();
        assert!(
            LocalCache::open_path_with_key_store(
                "personal",
                legacy.clone(),
                Arc::new(MemoryCacheKeyStore::default())
            )
            .is_err()
        );
        assert_eq!(std::fs::read(legacy).unwrap(), before);
    }

    #[test]
    fn missing_key_and_tampering_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let keys = Arc::new(MemoryCacheKeyStore::default());
        let cache = persisted_cache("personal", &root, keys.clone());
        cache
            .upsert_vault(&umbra_protocol::VaultResponse {
                vault_id: uuid::Uuid::new_v4(),
                org_id: None,
                name: "secret".to_owned(),
                kind: VaultKind::Personal,
                vault_revision: 1,
                access_revision: 1,
                current_key_generation: 1,
                needs_key_rotation: false,
            })
            .unwrap();
        keys.clear("personal").unwrap();
        assert!(
            LocalCache::open_path_with_key_store(
                "personal",
                root.path().join("cache.db"),
                keys.clone()
            )
            .is_err()
        );
        keys.set("personal", &LocalUnlockKey::generate()).unwrap();
        assert!(
            LocalCache::open_path_with_key_store("personal", root.path().join("cache.db"), keys)
                .is_err()
        );
    }

    #[test]
    fn profile_cache_dir_sanitizes_profile_names() {
        let base = std::path::PathBuf::from("/tmp/umbra-cache-test");
        let path = profile_cache_dir_from_base(&base, "miguel@example.com/local");

        assert_eq!(path, base.join("profiles").join("miguel_example.com_local"));
    }

    #[test]
    fn opens_cache_and_creates_schema() {
        let cache = LocalCache::open_in_memory("personal").unwrap();

        let tables = cache.table_names().unwrap();

        assert!(tables.contains(&"cache_meta".to_owned()));
        assert!(tables.contains(&"vaults".to_owned()));
        assert!(tables.contains(&"sync_state".to_owned()));
        assert!(tables.contains(&"vault_key_wrappings".to_owned()));
        assert!(tables.contains(&"item_revisions".to_owned()));
    }

    #[test]
    fn upserts_vault_metadata_and_finds_by_name() {
        let cache = LocalCache::open_in_memory("personal").unwrap();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();

        cache
            .upsert_vault(&umbra_protocol::VaultResponse {
                vault_id,
                org_id: None,
                name: "Personal".to_owned(),
                kind: umbra_core::VaultKind::Personal,
                vault_revision: 4,
                access_revision: 2,
                current_key_generation: 1,
                needs_key_rotation: false,
            })
            .unwrap();

        let vaults = cache.find_vaults_by_name("Personal").unwrap();
        assert_eq!(vaults.len(), 1);
        let vault = vaults[0].clone();
        assert_eq!(vault.vault_id, vault_id);
        assert_eq!(vault.name, "Personal");
        assert_eq!(vault.kind, "personal");
        assert_eq!(vault.latest_vault_revision, 4);
        assert_eq!(vault.latest_access_revision, 2);
        assert_eq!(vault.current_key_generation, 1);
        assert!(!vault.needs_key_rotation);
        assert_eq!(cache.list_vaults().unwrap(), vec![vault]);
        assert_eq!(cache.cached_vault_ids().unwrap(), vec![vault_id]);
    }

    #[test]
    fn finds_all_vaults_with_same_name() {
        let cache = LocalCache::open_in_memory("personal").unwrap();
        for vault_id in [
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap(),
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000011").unwrap(),
        ] {
            cache
                .upsert_vault(&umbra_protocol::VaultResponse {
                    vault_id,
                    org_id: None,
                    name: "Personal".to_owned(),
                    kind: umbra_core::VaultKind::Personal,
                    vault_revision: 1,
                    access_revision: 1,
                    current_key_generation: 1,
                    needs_key_rotation: false,
                })
                .unwrap();
        }

        assert_eq!(cache.find_vaults_by_name("Personal").unwrap().len(), 2);
    }

    #[test]
    fn upserts_sync_changes_and_tracks_cursor() {
        let mut cache = LocalCache::open_in_memory("personal").unwrap();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let item_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let wrapping_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let user_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let latest_wrapping_id =
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000005").unwrap();
        let changes = umbra_protocol::VaultSyncChanges {
            vault_id,
            latest_vault_revision: 7,
            latest_access_revision: 3,
            items: vec![umbra_protocol::ItemRevisionResponse {
                item_id,
                vault_id,
                revision: 2,
                vault_revision: 7,
                key_generation: 1,
                author_user_id: Some(user_id),
                envelope: serde_json::json!({"ciphertext": "encrypted"}),
            }],
            deleted_items: vec![],
            key_wrappings: vec![
                umbra_protocol::VaultKeyWrappingResponse {
                    id: wrapping_id,
                    vault_id,
                    user_id,
                    device_id: None,
                    wrapping_type: "user_public_key".to_owned(),
                    envelope: serde_json::json!({"wrapped": true}),
                    key_generation: 1,
                },
                umbra_protocol::VaultKeyWrappingResponse {
                    id: latest_wrapping_id,
                    vault_id,
                    user_id,
                    device_id: None,
                    wrapping_type: "user_public_key".to_owned(),
                    envelope: serde_json::json!({"wrapped": "latest"}),
                    key_generation: 2,
                },
            ],
            key_wrapping_metadata: vec![],
            conflicts: vec![],
        };

        cache.apply_sync_changes(&changes).unwrap();

        let sync_state = cache.sync_state(vault_id).unwrap().unwrap();
        assert_eq!(
            sync_state.latest_vault_revision,
            changes.latest_vault_revision
        );
        assert_eq!(
            sync_state.latest_access_revision,
            changes.latest_access_revision
        );
        assert_eq!(cache.list_item_revisions(vault_id).unwrap().len(), 1);
        assert_eq!(cache.list_key_wrappings(vault_id).unwrap().len(), 2);
        assert_eq!(
            cache.latest_key_wrapping(vault_id, user_id).unwrap(),
            Some(CachedKeyWrapping {
                id: latest_wrapping_id,
                vault_id,
                user_id,
                device_id: None,
                wrapping_type: "user_public_key".to_owned(),
                envelope: serde_json::json!({"wrapped": "latest"}),
                key_generation: 2,
            })
        );

        cache
            .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
                vault_id,
                latest_vault_revision: 8,
                latest_access_revision: 4,
                items: vec![],
                deleted_items: vec![],
                key_wrappings: vec![umbra_protocol::VaultKeyWrappingResponse {
                    id: latest_wrapping_id,
                    vault_id,
                    user_id,
                    device_id: None,
                    wrapping_type: "user_public_key".to_owned(),
                    envelope: serde_json::json!({"wrapped": "latest"}),
                    key_generation: 2,
                }],
                key_wrapping_metadata: vec![],
                conflicts: vec![],
            })
            .unwrap();

        assert_eq!(cache.list_key_wrappings(vault_id).unwrap().len(), 1);
        assert_eq!(
            cache.latest_key_wrapping(vault_id, user_id).unwrap(),
            Some(CachedKeyWrapping {
                id: latest_wrapping_id,
                vault_id,
                user_id,
                device_id: None,
                wrapping_type: "user_public_key".to_owned(),
                envelope: serde_json::json!({"wrapped": "latest"}),
                key_generation: 2,
            })
        );

        cache
            .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
                vault_id,
                latest_vault_revision: 9,
                latest_access_revision: 5,
                items: vec![],
                deleted_items: vec![],
                key_wrappings: vec![],
                key_wrapping_metadata: vec![],
                conflicts: vec![],
            })
            .unwrap();

        assert_eq!(cache.list_key_wrappings(vault_id).unwrap(), vec![]);
        assert_eq!(cache.latest_key_wrapping(vault_id, user_id).unwrap(), None);
    }

    #[test]
    fn apply_sync_changes_removes_deleted_items() {
        let mut cache = LocalCache::open_in_memory("delete-cache").unwrap();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000601").unwrap();
        let item_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000602").unwrap();

        cache
            .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
                vault_id,
                latest_vault_revision: 1,
                latest_access_revision: 1,
                items: vec![umbra_protocol::ItemRevisionResponse {
                    item_id,
                    vault_id,
                    revision: 1,
                    vault_revision: 1,
                    key_generation: 1,
                    author_user_id: None,
                    envelope: serde_json::json!({"ciphertext": "encrypted"}),
                }],
                deleted_items: vec![],
                key_wrappings: vec![],
                key_wrapping_metadata: vec![],
                conflicts: vec![],
            })
            .unwrap();
        assert_eq!(cache.list_latest_item_revisions(vault_id).unwrap().len(), 1);

        cache
            .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
                vault_id,
                latest_vault_revision: 2,
                latest_access_revision: 1,
                items: vec![],
                deleted_items: vec![item_id],
                key_wrappings: vec![],
                key_wrapping_metadata: vec![],
                conflicts: vec![],
            })
            .unwrap();

        assert!(
            cache
                .latest_item_revision(vault_id, item_id)
                .unwrap()
                .is_none()
        );
        assert!(
            cache
                .list_latest_item_revisions(vault_id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn sync_replaces_open_conflicts_atomically() {
        let mut cache = LocalCache::open_in_memory("conflicts").unwrap();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000701").unwrap();
        let initial_conflict_id =
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000702").unwrap();
        let replacement_conflict_id =
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000703").unwrap();
        let item_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000704").unwrap();
        cache
            .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
                vault_id,
                latest_vault_revision: 2,
                latest_access_revision: 1,
                items: vec![],
                deleted_items: vec![],
                key_wrappings: vec![],
                key_wrapping_metadata: vec![],
                conflicts: vec![umbra_protocol::ItemConflictResponse {
                    conflict_id: initial_conflict_id,
                    vault_id,
                    item_id,
                    base_revision: 1,
                    current_revision: 2,
                    candidate_kind: "update".to_owned(),
                    candidate_envelope: Some(serde_json::json!({"ciphertext":"sealed"})),
                    author_user_id: None,
                    state: "open".to_owned(),
                }],
            })
            .unwrap();

        cache
            .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
                vault_id,
                latest_vault_revision: 3,
                latest_access_revision: 1,
                items: vec![],
                deleted_items: vec![],
                key_wrappings: vec![],
                key_wrapping_metadata: vec![],
                conflicts: vec![umbra_protocol::ItemConflictResponse {
                    conflict_id: replacement_conflict_id,
                    vault_id,
                    item_id,
                    base_revision: 2,
                    current_revision: 3,
                    candidate_kind: "update".to_owned(),
                    candidate_envelope: Some(serde_json::json!({"ciphertext":"replacement"})),
                    author_user_id: None,
                    state: "open".to_owned(),
                }],
            })
            .unwrap();

        assert_eq!(
            cache.list_item_conflicts(vault_id).unwrap(),
            vec![CachedItemConflict {
                conflict_id: replacement_conflict_id,
                vault_id,
                item_id,
                base_revision: 2,
                current_revision: 3,
                candidate_kind: "update".to_owned(),
                candidate_envelope: Some(serde_json::json!({"ciphertext":"replacement"})),
                author_user_id: None,
                state: "open".to_owned(),
            }]
        );

        cache
            .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
                vault_id,
                latest_vault_revision: 4,
                latest_access_revision: 1,
                items: vec![],
                deleted_items: vec![],
                key_wrappings: vec![],
                key_wrapping_metadata: vec![],
                conflicts: vec![],
            })
            .unwrap();
        assert!(cache.list_item_conflicts(vault_id).unwrap().is_empty());
    }

    mod checkpoint_validation {
        use ed25519_dalek::SigningKey;
        use umbra_auth::verifying_key_to_b64;
        use umbra_crypto::checkpoints::{checkpoint_hash, sign_checkpoint};
        use umbra_protocol::{
            ItemRevisionResponse, SyncCheckpoint, VaultKeyWrappingMetadata,
            VaultKeyWrappingResponse, VaultSyncChanges,
        };

        use super::*;

        fn signing_key(seed: u8) -> SigningKey {
            SigningKey::from_bytes(&[seed; 32])
        }

        fn changes(vault_id: uuid::Uuid, revision: i64, ciphertext: &str) -> VaultSyncChanges {
            VaultSyncChanges {
                vault_id,
                latest_vault_revision: revision,
                latest_access_revision: 1,
                items: vec![ItemRevisionResponse {
                    item_id: uuid::Uuid::from_u128(2),
                    vault_id,
                    revision,
                    vault_revision: revision,
                    key_generation: 1,
                    author_user_id: None,
                    envelope: serde_json::json!({
                        "ciphertext": ciphertext,
                        "nonce": "opaque-nonce"
                    }),
                }],
                deleted_items: vec![],
                key_wrappings: vec![],
                key_wrapping_metadata: vec![],
                conflicts: vec![],
            }
        }

        fn trust(
            cache: &LocalCache,
            device_id: uuid::Uuid,
            key: &SigningKey,
        ) -> TrustedCheckpointDevice {
            let device = TrustedCheckpointDevice {
                device_id,
                public_key: verifying_key_to_b64(&key.verifying_key()),
                revoked: false,
            };
            cache.record_trusted_checkpoint_device(&device).unwrap();
            device
        }

        fn checkpoint(
            cache: &mut LocalCache,
            changes: &VaultSyncChanges,
            previous_checkpoint_hash: Option<String>,
            device_id: uuid::Uuid,
            key: &SigningKey,
        ) -> SyncCheckpoint {
            let state_commitment = cache.projected_state_commitment(changes).unwrap();
            sign_checkpoint(
                SyncCheckpoint {
                    vault_id: changes.vault_id,
                    vault_revision: changes.latest_vault_revision,
                    state_commitment,
                    previous_checkpoint_hash,
                    author_device_id: device_id,
                    signature: String::new(),
                },
                key,
            )
            .unwrap()
        }

        #[test]
        fn checkpoint_validation_records_valid_successor_and_changes_atomically() {
            let mut cache = LocalCache::open_in_memory("valid-checkpoint").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);

            let first_changes = changes(vault_id, 1, "encrypted-one");
            let first = checkpoint(&mut cache, &first_changes, None, device_id, &key);
            cache
                .verify_and_record_checkpoints(&first_changes, std::slice::from_ref(&first))
                .unwrap();
            let first_hash = checkpoint_hash(&first).unwrap();

            let second_changes = changes(vault_id, 2, "encrypted-two");
            let second = checkpoint(
                &mut cache,
                &second_changes,
                Some(first_hash),
                device_id,
                &key,
            );
            cache
                .verify_and_record_checkpoints(&second_changes, std::slice::from_ref(&second))
                .unwrap();

            let state = cache.integrity_state(vault_id).unwrap();
            assert!(!state.unsafe_sync);
            assert_eq!(state.verified_head.unwrap().checkpoint, second);
            assert_eq!(
                cache
                    .latest_item_revision(vault_id, uuid::Uuid::from_u128(2))
                    .unwrap()
                    .unwrap()
                    .envelope["ciphertext"],
                "encrypted-two"
            );
        }

        #[test]
        fn client_authors_missing_checkpoint_from_projected_ciphertext_state() {
            let mut cache = LocalCache::open_in_memory("checkpoint-author").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);

            let first_changes = changes(vault_id, 1, "encrypted-one");
            let first = cache
                .author_checkpoint(&first_changes, &[], device_id, &key)
                .unwrap();
            assert_eq!(first.previous_checkpoint_hash, None);
            umbra_crypto::checkpoints::verify_checkpoint(&first, &key.verifying_key()).unwrap();
            cache
                .verify_and_record_checkpoints(&first_changes, std::slice::from_ref(&first))
                .unwrap();

            let second_changes = changes(vault_id, 2, "encrypted-two");
            let second = cache
                .author_checkpoint(&second_changes, &[], device_id, &key)
                .unwrap();
            assert_eq!(
                second.previous_checkpoint_hash,
                Some(checkpoint_hash(&first).unwrap())
            );
            umbra_crypto::checkpoints::verify_checkpoint(&second, &key.verifying_key()).unwrap();
            cache
                .verify_and_record_checkpoints(&second_changes, std::slice::from_ref(&second))
                .unwrap();
            assert_eq!(
                cache
                    .integrity_state(vault_id)
                    .unwrap()
                    .verified_head
                    .unwrap()
                    .checkpoint,
                second
            );
        }

        #[test]
        fn checkpoint_commitment_binds_device_targeted_wrapping_metadata() {
            let mut cache = LocalCache::open_in_memory("checkpoint-device-wrapping").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let user_id = uuid::Uuid::from_u128(2);
            let first_device = uuid::Uuid::from_u128(3);
            let second_device = uuid::Uuid::from_u128(4);
            let mut first = changes(vault_id, 1, "encrypted");
            first.key_wrappings = vec![umbra_protocol::VaultKeyWrappingResponse {
                id: uuid::Uuid::from_u128(5),
                vault_id,
                user_id,
                device_id: Some(first_device),
                wrapping_type: "device_public_key".to_owned(),
                envelope: serde_json::json!({"ciphertext": "first"}),
                key_generation: 1,
            }];
            let mut second = first.clone();
            second.key_wrappings[0].device_id = Some(second_device);

            assert_ne!(
                cache.projected_state_commitment(&first).unwrap(),
                cache.projected_state_commitment(&second).unwrap(),
                "a checkpoint must bind the intended recipient device"
            );
        }

        #[test]
        fn device_scoped_sync_commits_all_metadata_without_caching_peer_envelopes() {
            let mut device_a_cache = LocalCache::open_in_memory("v3-device-a").unwrap();
            let mut device_b_cache = LocalCache::open_in_memory("v3-device-b").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let user_id = uuid::Uuid::from_u128(2);
            let device_a = uuid::Uuid::from_u128(3);
            let device_b = uuid::Uuid::from_u128(4);
            let wrapping_a = VaultKeyWrappingResponse {
                id: uuid::Uuid::from_u128(5),
                vault_id,
                user_id,
                device_id: Some(device_a),
                wrapping_type: "device_public_key".to_owned(),
                envelope: serde_json::json!({"ciphertext": "only-a"}),
                key_generation: 1,
            };
            let wrapping_b = VaultKeyWrappingResponse {
                id: uuid::Uuid::from_u128(6),
                vault_id,
                user_id,
                device_id: Some(device_b),
                wrapping_type: "device_public_key".to_owned(),
                envelope: serde_json::json!({"ciphertext": "only-b"}),
                key_generation: 1,
            };
            let metadata = [wrapping_a.clone(), wrapping_b.clone()]
                .into_iter()
                .map(|wrapping| VaultKeyWrappingMetadata {
                    id: wrapping.id,
                    vault_id: wrapping.vault_id,
                    user_id: wrapping.user_id,
                    device_id: wrapping.device_id,
                    wrapping_type: wrapping.wrapping_type,
                    key_generation: wrapping.key_generation,
                    envelope_hash: hash_json(&wrapping.envelope).unwrap(),
                })
                .collect::<Vec<_>>();
            let mut changes_a = changes(vault_id, 1, "shared-item");
            changes_a.key_wrappings = vec![wrapping_a];
            changes_a.key_wrapping_metadata = metadata.clone();
            let mut changes_b = changes(vault_id, 1, "shared-item");
            changes_b.key_wrappings = vec![wrapping_b];
            changes_b.key_wrapping_metadata = metadata;

            device_a_cache.apply_sync_changes(&changes_a).unwrap();
            device_b_cache.apply_sync_changes(&changes_b).unwrap();

            assert_eq!(
                device_a_cache
                    .projected_state_commitment(&changes_a)
                    .unwrap(),
                device_b_cache
                    .projected_state_commitment(&changes_b)
                    .unwrap()
            );
            let author_key = signing_key(7);
            trust(&device_a_cache, device_a, &author_key);
            trust(&device_b_cache, device_a, &author_key);
            let checkpoint = device_a_cache
                .author_checkpoint(&changes_a, &[], device_a, &author_key)
                .unwrap();
            device_a_cache
                .verify_and_record_checkpoints(&changes_a, std::slice::from_ref(&checkpoint))
                .unwrap();
            device_b_cache
                .verify_and_record_checkpoints(&changes_b, std::slice::from_ref(&checkpoint))
                .unwrap();
            assert_eq!(
                device_a_cache.list_key_wrappings(vault_id).unwrap().len(),
                1
            );
            assert_eq!(
                device_b_cache.list_key_wrappings(vault_id).unwrap().len(),
                1
            );
            assert_ne!(
                device_a_cache.list_key_wrappings(vault_id).unwrap()[0].envelope,
                device_b_cache.list_key_wrappings(vault_id).unwrap()[0].envelope
            );
        }

        #[test]
        fn two_devices_use_transferred_anchors_to_author_and_verify() {
            let mut first_cache = LocalCache::open_in_memory("author-device-a").unwrap();
            let mut second_cache = LocalCache::open_in_memory("author-device-b").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_a = uuid::Uuid::from_u128(9);
            let device_b = uuid::Uuid::from_u128(10);
            let key_a = signing_key(7);
            let key_b = signing_key(8);
            for cache in [&first_cache, &second_cache] {
                trust(cache, device_a, &key_a);
                trust(cache, device_b, &key_b);
            }

            let first_changes = changes(vault_id, 1, "created-by-a");
            let first = first_cache
                .author_checkpoint(&first_changes, &[], device_a, &key_a)
                .unwrap();
            for cache in [&mut first_cache, &mut second_cache] {
                cache
                    .verify_and_record_checkpoints(&first_changes, std::slice::from_ref(&first))
                    .unwrap();
            }

            let second_changes = changes(vault_id, 2, "updated-by-b");
            let second = second_cache
                .author_checkpoint(&second_changes, &[], device_b, &key_b)
                .unwrap();
            for cache in [&mut first_cache, &mut second_cache] {
                cache
                    .verify_and_record_checkpoints(&second_changes, std::slice::from_ref(&second))
                    .unwrap();
            }

            assert_eq!(
                first_cache
                    .integrity_state(vault_id)
                    .unwrap()
                    .verified_head
                    .unwrap()
                    .checkpoint,
                second
            );
            assert_eq!(
                second_cache
                    .integrity_state(vault_id)
                    .unwrap()
                    .verified_head
                    .unwrap()
                    .checkpoint,
                second
            );
        }

        #[test]
        fn malicious_checkpoint_rollback_is_quarantined_without_applying_payload() {
            let mut cache = LocalCache::open_in_memory("rollback").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);

            let first_changes = changes(vault_id, 1, "trusted-first");
            let first = checkpoint(&mut cache, &first_changes, None, device_id, &key);
            cache
                .verify_and_record_checkpoints(&first_changes, std::slice::from_ref(&first))
                .unwrap();
            let current_changes = changes(vault_id, 2, "trusted-current");
            let current = checkpoint(
                &mut cache,
                &current_changes,
                Some(checkpoint_hash(&first).unwrap()),
                device_id,
                &key,
            );
            cache
                .verify_and_record_checkpoints(&current_changes, std::slice::from_ref(&current))
                .unwrap();
            let trusted_hash = checkpoint_hash(&current).unwrap();

            let result =
                cache.verify_and_record_checkpoints(&first_changes, std::slice::from_ref(&first));

            assert!(matches!(
                result,
                Err(CliError::SyncIntegrity {
                    vault_id: id,
                    revision: 1,
                    ..
                }) if id == vault_id
            ));
            let state = cache.integrity_state(vault_id).unwrap();
            assert!(state.unsafe_sync);
            assert_eq!(state.verified_head.unwrap().checkpoint_hash, trusted_hash);
            assert_eq!(state.findings[0].code, "non_monotonic_revision");
            assert_eq!(
                cache
                    .latest_item_revision(vault_id, uuid::Uuid::from_u128(2))
                    .unwrap()
                    .unwrap()
                    .envelope["ciphertext"],
                "trusted-current"
            );
        }

        #[test]
        fn checkpoint_validation_quarantines_invalid_signature_untrusted_signer_and_commitment() {
            for case in [
                "invalid_signature",
                "untrusted_signer",
                "commitment_mismatch",
            ] {
                let mut cache = LocalCache::open_in_memory(case).unwrap();
                let vault_id = uuid::Uuid::from_u128(1);
                let trusted_device = uuid::Uuid::from_u128(9);
                let untrusted_device = uuid::Uuid::from_u128(10);
                let trusted_key = signing_key(7);
                let untrusted_key = signing_key(8);
                trust(&cache, trusted_device, &trusted_key);
                let changes = changes(vault_id, 1, "encrypted");
                let mut candidate =
                    checkpoint(&mut cache, &changes, None, trusted_device, &trusted_key);
                match case {
                    "invalid_signature" => candidate.signature.push('x'),
                    "untrusted_signer" => {
                        candidate = checkpoint(
                            &mut cache,
                            &changes,
                            None,
                            untrusted_device,
                            &untrusted_key,
                        );
                    }
                    "commitment_mismatch" => {
                        candidate = sign_checkpoint(
                            SyncCheckpoint {
                                state_commitment: umbra_crypto::checkpoints::state_commitment([
                                    b"altered-state".to_vec(),
                                ]),
                                ..candidate
                            },
                            &trusted_key,
                        )
                        .unwrap();
                    }
                    _ => unreachable!(),
                }

                let result =
                    cache.verify_and_record_checkpoints(&changes, std::slice::from_ref(&candidate));

                assert!(matches!(result, Err(CliError::SyncIntegrity { .. })));
                let state = cache.integrity_state(vault_id).unwrap();
                assert!(state.unsafe_sync);
                assert_eq!(state.findings[0].code, case);
                assert!(state.verified_head.is_none());
                assert!(
                    cache
                        .latest_item_revision(vault_id, uuid::Uuid::from_u128(2))
                        .unwrap()
                        .is_none()
                );
            }
        }

        #[test]
        fn checkpoint_validation_rejects_missing_predecessor_and_revoked_signer() {
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);

            let mut missing_cache = LocalCache::open_in_memory("missing-predecessor").unwrap();
            trust(&missing_cache, device_id, &key);
            let first_changes = changes(vault_id, 1, "first");
            let first = checkpoint(&mut missing_cache, &first_changes, None, device_id, &key);
            missing_cache
                .verify_and_record_checkpoints(&first_changes, std::slice::from_ref(&first))
                .unwrap();
            let skipped_changes = changes(vault_id, 3, "skipped-revision");
            let skipped = checkpoint(
                &mut missing_cache,
                &skipped_changes,
                Some(umbra_crypto::checkpoints::state_commitment([
                    b"omitted-predecessor".to_vec(),
                ])),
                device_id,
                &key,
            );
            assert!(matches!(
                missing_cache.verify_and_record_checkpoints(
                    &skipped_changes,
                    std::slice::from_ref(&skipped)
                ),
                Err(CliError::SyncIntegrity { .. })
            ));
            assert_eq!(
                missing_cache.integrity_findings(vault_id).unwrap()[0].code,
                "missing_predecessor"
            );

            let mut revoked_cache = LocalCache::open_in_memory("revoked-signer").unwrap();
            revoked_cache
                .record_trusted_checkpoint_device(&TrustedCheckpointDevice {
                    device_id,
                    public_key: verifying_key_to_b64(&key.verifying_key()),
                    revoked: true,
                })
                .unwrap();
            let revoked_changes = changes(vault_id, 1, "revoked");
            let revoked = checkpoint(&mut revoked_cache, &revoked_changes, None, device_id, &key);
            assert!(matches!(
                revoked_cache.verify_and_record_checkpoints(
                    &revoked_changes,
                    std::slice::from_ref(&revoked)
                ),
                Err(CliError::SyncIntegrity { .. })
            ));
            assert_eq!(
                revoked_cache.integrity_findings(vault_id).unwrap()[0].code,
                "revoked_signer"
            );
        }

        #[test]
        fn checkpoint_validation_persists_transport_downgrade_evidence() {
            let mut cache = LocalCache::open_in_memory("transport-downgrade").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);

            cache
                .quarantine_transport_failure(vault_id, 4, "protocol-v1", "protocol_downgrade")
                .unwrap();

            let state = cache.integrity_state(vault_id).unwrap();
            assert!(state.unsafe_sync);
            assert_eq!(state.findings[0].code, "protocol_downgrade");
            assert_eq!(state.findings[0].checkpoint_hash, "protocol-v1");
        }

        #[test]
        fn checkpoint_validation_rejects_cross_vault_nested_records() {
            let mut cache = LocalCache::open_in_memory("cross-vault").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let other_vault_id = uuid::Uuid::from_u128(99);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);
            let mut malicious_changes = changes(vault_id, 1, "hidden-cross-vault-record");
            malicious_changes.items[0].vault_id = other_vault_id;
            let signed = checkpoint(&mut cache, &malicious_changes, None, device_id, &key);

            assert!(matches!(
                cache.verify_and_record_checkpoints(
                    &malicious_changes,
                    std::slice::from_ref(&signed)
                ),
                Err(CliError::SyncIntegrity { .. })
            ));
            assert_eq!(
                cache.integrity_findings(vault_id).unwrap()[0].code,
                "state_scope_mismatch"
            );
            assert!(
                cache
                    .latest_item_revision(other_vault_id, uuid::Uuid::from_u128(2))
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn checkpoint_validation_rejects_access_revision_rollback() {
            let mut cache = LocalCache::open_in_memory("access-rollback").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);
            let mut current_changes = changes(vault_id, 1, "trusted");
            current_changes.latest_access_revision = 5;
            let current = checkpoint(&mut cache, &current_changes, None, device_id, &key);
            cache
                .verify_and_record_checkpoints(&current_changes, std::slice::from_ref(&current))
                .unwrap();

            let mut rollback_changes = current_changes.clone();
            rollback_changes.latest_access_revision = 4;
            assert!(matches!(
                cache.verify_and_record_checkpoints(&rollback_changes, &[]),
                Err(CliError::SyncIntegrity { .. })
            ));
            assert_eq!(
                cache.integrity_findings(vault_id).unwrap()[0].code,
                "access_revision_rollback"
            );
            assert_eq!(
                cache
                    .sync_state(vault_id)
                    .unwrap()
                    .unwrap()
                    .latest_access_revision,
                5
            );
        }

        #[test]
        fn malicious_checkpoint_equivocation_preserves_both_signed_records() {
            let mut cache = LocalCache::open_in_memory("equivocation").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);
            let original_changes = changes(vault_id, 1, "branch-a");
            let original = checkpoint(&mut cache, &original_changes, None, device_id, &key);
            cache
                .verify_and_record_checkpoints(&original_changes, std::slice::from_ref(&original))
                .unwrap();

            let conflicting_changes = changes(vault_id, 1, "branch-b");
            let conflicting = checkpoint(&mut cache, &conflicting_changes, None, device_id, &key);
            let result = cache.verify_and_record_checkpoints(
                &conflicting_changes,
                std::slice::from_ref(&conflicting),
            );

            assert!(matches!(result, Err(CliError::SyncIntegrity { .. })));
            let bundle = cache.export_checkpoint_evidence(vault_id).unwrap();
            assert!(bundle.unsafe_sync);
            assert_eq!(bundle.observed_checkpoints.len(), 2);
            assert!(bundle.observed_checkpoints.contains(&original));
            assert!(bundle.observed_checkpoints.contains(&conflicting));
            assert_eq!(bundle.findings[0].code, "equivocation");
        }

        #[test]
        fn sync_integrity_export_contains_no_payloads_wrappings_or_secrets() {
            let mut cache = LocalCache::open_in_memory("redacted-export").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);
            let changes = changes(
                vault_id,
                1,
                "PLAINTEXT_SECRET_CIPHERTEXT_ENVELOPE_TOKEN_VAULT_KEY_WRAPPING",
            );
            let signed = checkpoint(&mut cache, &changes, None, device_id, &key);
            cache
                .verify_and_record_checkpoints(&changes, std::slice::from_ref(&signed))
                .unwrap();

            let encoded =
                serde_json::to_string(&cache.export_checkpoint_evidence(vault_id).unwrap())
                    .unwrap();
            for forbidden in [
                "PLAINTEXT_SECRET",
                "CIPHERTEXT_ENVELOPE",
                "TOKEN",
                "VAULT_KEY_WRAPPING",
                "\"envelope\"",
                "\"plaintext\"",
                "\"wrapping\"",
                "\"private_key\"",
            ] {
                assert!(!encoded.contains(forbidden), "export leaked {forbidden}");
            }
        }

        #[test]
        fn sync_integrity_export_redacts_malformed_attacker_controlled_metadata() {
            let mut cache = LocalCache::open_in_memory("malformed-export").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_id = uuid::Uuid::from_u128(9);
            let key = signing_key(7);
            trust(&cache, device_id, &key);
            let changes = changes(vault_id, 1, "encrypted");
            let mut malicious = checkpoint(&mut cache, &changes, None, device_id, &key);
            malicious.signature =
                "PLAINTEXT_SECRET_CIPHERTEXT_ENVELOPE_TOKEN_VAULT_KEY_WRAPPING".to_owned();
            assert!(matches!(
                cache.verify_and_record_checkpoints(&changes, std::slice::from_ref(&malicious)),
                Err(CliError::SyncIntegrity { .. })
            ));

            let encoded =
                serde_json::to_string(&cache.export_checkpoint_evidence(vault_id).unwrap())
                    .unwrap();
            for forbidden in [
                "PLAINTEXT_SECRET",
                "CIPHERTEXT_ENVELOPE",
                "TOKEN",
                "VAULT_KEY_WRAPPING",
            ] {
                assert!(!encoded.contains(forbidden), "export leaked {forbidden}");
            }
            assert!(encoded.contains("invalid_signature"));
        }

        #[test]
        fn honest_devices_converge_on_the_same_verified_checkpoint() {
            let mut first_cache = LocalCache::open_in_memory("first").unwrap();
            let mut second_cache = LocalCache::open_in_memory("second").unwrap();
            let vault_id = uuid::Uuid::from_u128(1);
            let device_a = uuid::Uuid::from_u128(9);
            let device_b = uuid::Uuid::from_u128(10);
            let key_a = signing_key(7);
            let key_b = signing_key(8);
            for cache in [&first_cache, &second_cache] {
                trust(cache, device_a, &key_a);
                trust(cache, device_b, &key_b);
            }

            let first_changes = changes(vault_id, 1, "created-by-a");
            let first = checkpoint(&mut first_cache, &first_changes, None, device_a, &key_a);
            for cache in [&mut first_cache, &mut second_cache] {
                cache
                    .verify_and_record_checkpoints(&first_changes, std::slice::from_ref(&first))
                    .unwrap();
            }

            let mut conflict_changes = changes(vault_id, 2, "updated-by-b");
            conflict_changes.conflicts = vec![umbra_protocol::ItemConflictResponse {
                conflict_id: uuid::Uuid::from_u128(3),
                vault_id,
                item_id: uuid::Uuid::from_u128(2),
                base_revision: 1,
                current_revision: 2,
                candidate_kind: "update".to_owned(),
                candidate_envelope: Some(serde_json::json!({
                    "ciphertext": "conflicting-encrypted-candidate"
                })),
                author_user_id: None,
                state: "open".to_owned(),
            }];
            let conflict_checkpoint = checkpoint(
                &mut first_cache,
                &conflict_changes,
                Some(checkpoint_hash(&first).unwrap()),
                device_b,
                &key_b,
            );
            for cache in [&mut first_cache, &mut second_cache] {
                cache
                    .verify_and_record_checkpoints(
                        &conflict_changes,
                        std::slice::from_ref(&conflict_checkpoint),
                    )
                    .unwrap();
            }

            let resolved_changes = changes(vault_id, 3, "resolved-by-a");
            let resolved_checkpoint = checkpoint(
                &mut first_cache,
                &resolved_changes,
                Some(checkpoint_hash(&conflict_checkpoint).unwrap()),
                device_a,
                &key_a,
            );
            for cache in [&mut first_cache, &mut second_cache] {
                cache
                    .verify_and_record_checkpoints(
                        &resolved_changes,
                        std::slice::from_ref(&resolved_checkpoint),
                    )
                    .unwrap();
            }

            let first_head = first_cache
                .integrity_state(vault_id)
                .unwrap()
                .verified_head
                .unwrap();
            let second_head = second_cache
                .integrity_state(vault_id)
                .unwrap()
                .verified_head
                .unwrap();
            assert_eq!(first_head.checkpoint_hash, second_head.checkpoint_hash);
            assert_eq!(first_head.checkpoint, second_head.checkpoint);
            assert_eq!(first_head.checkpoint, resolved_checkpoint);
            assert!(
                first_cache
                    .list_item_conflicts(vault_id)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                second_cache
                    .list_item_conflicts(vault_id)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                first_cache
                    .latest_item_revision(vault_id, uuid::Uuid::from_u128(2))
                    .unwrap(),
                second_cache
                    .latest_item_revision(vault_id, uuid::Uuid::from_u128(2))
                    .unwrap()
            );
        }
    }
}
