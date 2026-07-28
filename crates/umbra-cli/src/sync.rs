use crate::cache::LocalCache;
use crate::config::ProfileConfig;
use crate::error::CliError;
use crate::http::UmbraHttpClient;
use serde::Serialize;
use umbra_core::{RevisionId, VaultId};
use umbra_protocol::{
    CreateSyncCheckpointRequest, SYNC_INTEGRITY_PROTOCOL_VERSION, SyncCheckpoint, SyncRequest,
    SyncResponse, SyncStatusRequest, SyncStatusResponse, VaultStatus, VaultStatusCursor,
    VaultSyncChanges, VaultSyncCursor,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncMode {
    IfChanged,
    Always,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncOutcome {
    pub synced: bool,
    pub latest_vault_revision: RevisionId,
    pub latest_access_revision: RevisionId,
}

pub async fn ensure_vault_synced(
    profile: &ProfileConfig,
    cache: &mut LocalCache,
    vault_id: VaultId,
    mode: SyncMode,
) -> Result<SyncOutcome, CliError> {
    if cache.is_sync_unsafe(vault_id)? {
        return Err(cache.integrity_error(vault_id)?);
    }
    let state = cache.sync_state(vault_id)?;
    let known_vault_revision = state
        .as_ref()
        .map(|state| state.latest_vault_revision)
        .unwrap_or(0);
    let known_access_revision = state
        .as_ref()
        .map(|state| state.latest_access_revision)
        .unwrap_or(0);
    let verified_head_revision = cache
        .integrity_state(vault_id)?
        .verified_head
        .map(|head| head.checkpoint.vault_revision);
    let integrity_cursor_revision = verified_head_revision.unwrap_or(0);

    if mode == SyncMode::Offline {
        return Ok(SyncOutcome {
            synced: false,
            latest_vault_revision: known_vault_revision,
            latest_access_revision: known_access_revision,
        });
    }

    record_local_trust_anchor(profile, cache)?;
    let client = UmbraHttpClient::new(profile)?;

    match mode {
        SyncMode::Offline => unreachable!("offline mode returned before HTTP client creation"),
        SyncMode::Always => {
            sync_vault(&client, profile, cache, vault_id, integrity_cursor_revision).await
        }
        SyncMode::IfChanged => {
            let response: SyncStatusResponse = client
                .post(
                    "/api/v1/sync/status",
                    &SyncStatusRequest {
                        protocol_version: SYNC_INTEGRITY_PROTOCOL_VERSION,
                        vaults: vec![VaultStatusCursor {
                            vault_id,
                            known_vault_revision: integrity_cursor_revision,
                            known_access_revision,
                        }],
                    },
                )
                .await?;
            if response.protocol_version != SYNC_INTEGRITY_PROTOCOL_VERSION {
                cache.quarantine_transport_failure(
                    vault_id,
                    integrity_cursor_revision,
                    &format!("protocol-version-{}", response.protocol_version),
                    "protocol_downgrade",
                )?;
                return Err(cache.integrity_error(vault_id)?);
            }
            let matching_statuses = response
                .vaults
                .iter()
                .filter(|status| status.vault_id == vault_id)
                .collect::<Vec<_>>();
            let [status] = matching_statuses.as_slice() else {
                let code = if matching_statuses.is_empty() {
                    "missing_vault_status"
                } else {
                    "duplicate_vault_status"
                };
                cache.quarantine_transport_failure(
                    vault_id,
                    integrity_cursor_revision,
                    "missing",
                    code,
                )?;
                return Err(cache.integrity_error(vault_id)?);
            };
            let status = Some(*status);

            if should_sync(
                state.is_none() || verified_head_revision.is_none(),
                integrity_cursor_revision,
                known_access_revision,
                status,
            ) {
                sync_vault(&client, profile, cache, vault_id, integrity_cursor_revision).await
            } else if let Some(status) = status {
                Ok(SyncOutcome {
                    synced: false,
                    latest_vault_revision: status.latest_vault_revision,
                    latest_access_revision: status.latest_access_revision,
                })
            } else {
                Ok(SyncOutcome {
                    synced: false,
                    latest_vault_revision: known_vault_revision,
                    latest_access_revision: known_access_revision,
                })
            }
        }
    }
}

async fn sync_vault(
    client: &UmbraHttpClient,
    profile: &ProfileConfig,
    cache: &mut LocalCache,
    vault_id: VaultId,
    since_vault_revision: RevisionId,
) -> Result<SyncOutcome, CliError> {
    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra login` first",
    ))?;
    let response: SyncResponse = client
        .post(
            "/api/v1/sync",
            &SyncRequest {
                protocol_version: SYNC_INTEGRITY_PROTOCOL_VERSION,
                device_id,
                vaults: vec![VaultSyncCursor {
                    vault_id,
                    since_vault_revision,
                }],
            },
        )
        .await?;

    if response.protocol_version != SYNC_INTEGRITY_PROTOCOL_VERSION {
        cache.quarantine_transport_failure(
            vault_id,
            since_vault_revision,
            &format!("protocol-version-{}", response.protocol_version),
            "protocol_downgrade",
        )?;
        return Err(cache.integrity_error(vault_id)?);
    }
    let matching_changes = response
        .vaults
        .iter()
        .filter(|changes| changes.vault_id == vault_id)
        .collect::<Vec<_>>();
    let [changes] = matching_changes.as_slice() else {
        let code = if matching_changes.is_empty() {
            "missing_vault_response"
        } else {
            "duplicate_vault_response"
        };
        cache.quarantine_transport_failure(vault_id, since_vault_revision, "missing", code)?;
        return Err(cache.integrity_error(vault_id)?);
    };
    let checkpoints = response
        .checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.vault_id == vault_id)
        .cloned()
        .collect::<Vec<_>>();
    let allow_genesis_authoring = since_vault_revision == 0
        && checkpoints.is_empty()
        && cache.integrity_state(vault_id)?.verified_head.is_none();
    apply_or_publish_checkpoint(
        client,
        profile,
        cache,
        changes,
        checkpoints,
        allow_genesis_authoring,
    )
    .await?;
    Ok(SyncOutcome {
        synced: true,
        latest_vault_revision: changes.latest_vault_revision,
        latest_access_revision: changes.latest_access_revision,
    })
}

pub async fn publish_checkpoint_after_mutation(
    profile: &ProfileConfig,
    cache: &mut LocalCache,
    vault_id: VaultId,
) -> Result<SyncOutcome, CliError> {
    if cache.is_sync_unsafe(vault_id)? {
        return Err(cache.integrity_error(vault_id)?);
    }
    record_local_trust_anchor(profile, cache)?;
    let client = UmbraHttpClient::new(profile)?;
    let since_vault_revision = cache
        .integrity_state(vault_id)?
        .verified_head
        .map(|head| head.checkpoint.vault_revision)
        .unwrap_or(0);
    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra login` first",
    ))?;
    let response: SyncResponse = client
        .post(
            "/api/v1/sync",
            &SyncRequest {
                protocol_version: SYNC_INTEGRITY_PROTOCOL_VERSION,
                device_id,
                vaults: vec![VaultSyncCursor {
                    vault_id,
                    since_vault_revision,
                }],
            },
        )
        .await?;
    if response.protocol_version != SYNC_INTEGRITY_PROTOCOL_VERSION {
        cache.quarantine_transport_failure(
            vault_id,
            since_vault_revision,
            &format!("protocol-version-{}", response.protocol_version),
            "protocol_downgrade",
        )?;
        return Err(cache.integrity_error(vault_id)?);
    }
    let matching_changes = response
        .vaults
        .iter()
        .filter(|changes| changes.vault_id == vault_id)
        .collect::<Vec<_>>();
    let [changes] = matching_changes.as_slice() else {
        let code = if matching_changes.is_empty() {
            "missing_vault_response"
        } else {
            "duplicate_vault_response"
        };
        cache.quarantine_transport_failure(vault_id, since_vault_revision, "missing", code)?;
        return Err(cache.integrity_error(vault_id)?);
    };
    let checkpoints = response
        .checkpoints
        .into_iter()
        .filter(|checkpoint| checkpoint.vault_id == vault_id)
        .collect();
    apply_or_publish_checkpoint(&client, profile, cache, changes, checkpoints, true).await?;
    Ok(SyncOutcome {
        synced: true,
        latest_vault_revision: changes.latest_vault_revision,
        latest_access_revision: changes.latest_access_revision,
    })
}

async fn apply_or_publish_checkpoint(
    client: &UmbraHttpClient,
    profile: &ProfileConfig,
    cache: &mut LocalCache,
    changes: &VaultSyncChanges,
    mut checkpoints: Vec<SyncCheckpoint>,
    allow_authoring: bool,
) -> Result<(), CliError> {
    let has_latest = checkpoints
        .iter()
        .any(|checkpoint| checkpoint.vault_revision == changes.latest_vault_revision);
    if has_latest || !allow_authoring {
        return cache.verify_and_record_checkpoints(changes, &checkpoints);
    }

    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra login` first",
    ))?;
    let signing_key = profile
        .device_private_key
        .as_deref()
        .ok_or(CliError::Input(
            "profile has no device signing key; run `umbra login` first",
        ))
        .and_then(crate::keys::DeviceSigningKey::from_base64url)?;
    let candidate =
        cache.author_checkpoint(changes, &checkpoints, device_id, signing_key.signing_key())?;
    let published: SyncCheckpoint = client
        .post(
            &format!("/api/v1/vaults/{}/checkpoints", changes.vault_id),
            &CreateSyncCheckpointRequest {
                protocol_version: SYNC_INTEGRITY_PROTOCOL_VERSION,
                checkpoint: candidate.clone(),
            },
        )
        .await?;
    if published != candidate {
        cache.quarantine_transport_failure(
            changes.vault_id,
            changes.latest_vault_revision,
            "mismatched-checkpoint-response",
            "checkpoint_publish_mismatch",
        )?;
        return Err(cache.integrity_error(changes.vault_id)?);
    }
    checkpoints.push(published);
    cache.verify_and_record_checkpoints(changes, &checkpoints)
}

pub(crate) fn record_local_trust_anchor(
    profile: &ProfileConfig,
    cache: &LocalCache,
) -> Result<(), CliError> {
    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra login` first",
    ))?;
    let encoded_key = profile
        .device_private_key
        .as_deref()
        .ok_or(CliError::Input(
            "profile has no device signing key; run `umbra login` first",
        ))?;
    let key = crate::keys::DeviceSigningKey::from_base64url(encoded_key)?;
    cache.record_trusted_checkpoint_device(&crate::cache::TrustedCheckpointDevice {
        device_id,
        public_key: key.public_key_base64url(),
        revoked: false,
    })
}

fn should_sync(
    has_no_state: bool,
    known_vault_revision: RevisionId,
    known_access_revision: RevisionId,
    status: Option<&VaultStatus>,
) -> bool {
    has_no_state
        || status
            .map(|status| {
                status.items_changed
                    || status.access_changed
                    || status.latest_vault_revision != known_vault_revision
                    || status.latest_access_revision != known_access_revision
            })
            .unwrap_or(false)
}

#[cfg(test)]
mod sync_policy {
    use super::*;

    #[test]
    fn sync_modes_compare_as_expected() {
        assert!(SyncMode::IfChanged < SyncMode::Always);
        assert!(SyncMode::Always < SyncMode::Offline);
    }
}
