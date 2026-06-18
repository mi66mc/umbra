#![allow(dead_code)]

use crate::cache::LocalCache;
use crate::config::ProfileConfig;
use crate::error::CliError;
use crate::http::UmbraHttpClient;
use umbra_core::{RevisionId, VaultId};
use umbra_protocol::{
    PROTOCOL_VERSION, SyncRequest, SyncResponse, SyncStatusRequest, SyncStatusResponse,
    VaultStatus, VaultStatusCursor, VaultSyncChanges, VaultSyncCursor,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncMode {
    IfChanged,
    Always,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    let state = cache.sync_state(vault_id)?;
    let known_vault_revision = state
        .as_ref()
        .map(|state| state.latest_vault_revision)
        .unwrap_or(0);
    let known_access_revision = state
        .as_ref()
        .map(|state| state.latest_access_revision)
        .unwrap_or(0);

    if mode == SyncMode::Offline {
        return Ok(SyncOutcome {
            synced: false,
            latest_vault_revision: known_vault_revision,
            latest_access_revision: known_access_revision,
        });
    }

    let client = UmbraHttpClient::new(profile)?;

    match mode {
        SyncMode::Offline => unreachable!("offline mode returned before HTTP client creation"),
        SyncMode::Always => {
            sync_vault(
                &client,
                profile,
                cache,
                vault_id,
                known_vault_revision,
                known_access_revision,
            )
            .await
        }
        SyncMode::IfChanged => {
            let response: SyncStatusResponse = client
                .post(
                    "/api/v1/sync/status",
                    &SyncStatusRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vaults: vec![VaultStatusCursor {
                            vault_id,
                            known_vault_revision,
                            known_access_revision,
                        }],
                    },
                )
                .await?;
            let status = response
                .vaults
                .iter()
                .find(|status| status.vault_id == vault_id);

            if should_sync(state.is_none(), status) {
                sync_vault(
                    &client,
                    profile,
                    cache,
                    vault_id,
                    known_vault_revision,
                    known_access_revision,
                )
                .await
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
    known_access_revision: RevisionId,
) -> Result<SyncOutcome, CliError> {
    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra login` first",
    ))?;
    let response: SyncResponse = client
        .post(
            "/api/v1/sync",
            &SyncRequest {
                protocol_version: PROTOCOL_VERSION,
                device_id,
                vaults: vec![VaultSyncCursor {
                    vault_id,
                    since_vault_revision,
                }],
            },
        )
        .await?;

    let changes = response
        .vaults
        .iter()
        .find(|changes| changes.vault_id == vault_id);
    if let Some(changes) = changes {
        apply_sync_changes(cache, changes)?;
        Ok(SyncOutcome {
            synced: true,
            latest_vault_revision: changes.latest_vault_revision,
            latest_access_revision: changes.latest_access_revision,
        })
    } else {
        Ok(SyncOutcome {
            synced: true,
            latest_vault_revision: since_vault_revision,
            latest_access_revision: known_access_revision,
        })
    }
}

fn apply_sync_changes(cache: &mut LocalCache, changes: &VaultSyncChanges) -> Result<(), CliError> {
    cache.apply_sync_changes(changes)
}

fn should_sync(has_no_state: bool, status: Option<&VaultStatus>) -> bool {
    has_no_state
        || status
            .map(|status| status.items_changed || status.access_changed)
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
