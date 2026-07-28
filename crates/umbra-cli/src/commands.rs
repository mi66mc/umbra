use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use umbra_core::{
    ItemId, ItemKind, ItemPlaintextV1, MemberState, OrgRole, RevisionId, UserId, VaultId,
    VaultKind, VaultRole,
};
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, DeviceBootstrapBundleV1, DeviceBootstrapEnvelopeV1,
    DeviceCheckpointTrustAnchorV1, MasterPassword, RecoveryChallengeEnvelopeV1, UserPrivateKey,
    UserPublicKey, VaultKey, VaultKeyWrappingEnvelopeV1, decrypt_device_bootstrap_bundle,
    decrypt_item, decrypt_recovery_challenge, encrypt_device_bootstrap_bundle, encrypt_item,
    generate_user_keypair, generate_vault_key, unwrap_vault_key, wrap_vault_key_for_user,
};
use umbra_protocol::{
    AcceptInviteRequest, AddOrgMemberRequest, AddVaultMemberRequest, ApprovalLookupRequest,
    ApproveDeviceRequest, CreateItemRequest, CreateOrgRequest, CreateOrgVaultRequest,
    CreateVaultRequest, DEVICE_SCOPED_WRAPPING_PROTOCOL_VERSION, DeleteItemRequest,
    DeviceBootstrapResponse, DeviceResponse, InviteMemberRequest, InviteResponse,
    ItemRevisionResponse, OrgMemberResponse, OrgResponse, PROTOCOL_VERSION, PendingDeviceSummary,
    PendingInviteResponse, RecoverTrustRequest, RecoverTrustResponse,
    RecoveryChallengeStartRequest, RecoveryChallengeStartResponse, RejectInviteRequest,
    ResolveItemConflictRequest, ResolveItemConflictResponse, RotateVaultKeyRequest,
    RotationItemRevision, RotationStatusResponse, RotationVaultKeyWrapping,
    SYNC_INTEGRITY_PROTOCOL_VERSION, SyncRequest, SyncResponse, UpdateItemRequest,
    UserLookupRequest, UserLookupResponse, VaultMemberResponse, VaultResponse, VaultSyncCursor,
};
use uuid::Uuid;

use crate::config::{
    CliConfig, active_profile, active_profile_mut, save_config, set_active_profile,
};
use crate::error::CliError;
use crate::http::{PublicHttpClient, UmbraHttpClient};
use crate::keys::DeviceSigningKey;
use crate::output::{OutputMode, print_json};
use crate::{
    AuthCommand, CacheCommand, Command, ConflictCommand, CryptoCommand, DeviceCommand,
    EmergencyKitCommand, EnvCommand, InviteCommand, ItemCommand, OrgCommand, ProfileCommand,
    SecretCommand, SyncCommand, SyncIntegrityCommand, TokenCommand, VaultCommand,
};

trait OutputModeExt {
    fn is_json(&self) -> bool;
}

impl OutputModeExt for OutputMode {
    fn is_json(&self) -> bool {
        matches!(self, &Self::Json)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ItemEnvelopeWrapper {
    kind: String,
    crypto: CryptoEnvelopeV1,
}

#[derive(Serialize)]
struct ConflictListEntry {
    conflict_id: Uuid,
    item_id: Uuid,
    base_revision: i64,
    current_revision: i64,
    candidate_kind: String,
    author_user_id: Option<Uuid>,
    state: String,
}

fn conflict_list_json(conflicts: &[crate::cache::CachedItemConflict]) -> Vec<ConflictListEntry> {
    conflicts
        .iter()
        .map(|conflict| ConflictListEntry {
            conflict_id: conflict.conflict_id,
            item_id: conflict.item_id,
            base_revision: conflict.base_revision,
            current_revision: conflict.current_revision,
            candidate_kind: conflict.candidate_kind.clone(),
            author_user_id: conflict.author_user_id,
            state: conflict.state.clone(),
        })
        .collect()
}

fn conflict_list_table_rows(conflicts: &[crate::cache::CachedItemConflict]) -> Vec<Vec<String>> {
    conflict_list_json(conflicts)
        .into_iter()
        .map(|conflict| {
            vec![
                conflict.conflict_id.to_string(),
                conflict.item_id.to_string(),
                conflict.base_revision.to_string(),
                conflict.current_revision.to_string(),
                conflict.candidate_kind,
                conflict
                    .author_user_id
                    .map(|author| author.to_string())
                    .unwrap_or_default(),
                conflict.state,
            ]
        })
        .collect()
}

pub async fn run(
    command: Command,
    mut config: CliConfig,
    output: OutputMode,
) -> Result<(), CliError> {
    match command {
        Command::Conflict(ConflictCommand::List { vault_id, vault }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
            let conflicts = cache.list_item_conflicts(vault_id)?;
            if output.is_json() {
                print_json(&conflict_list_json(&conflicts))
            } else {
                let rows = conflict_list_table_rows(&conflicts);
                crate::output::print_table(
                    &[
                        "conflict_id",
                        "item_id",
                        "base",
                        "current",
                        "kind",
                        "author_user_id",
                        "state",
                    ],
                    &rows,
                );
                Ok(())
            }
        }
        Command::Conflict(ConflictCommand::Show {
            conflict_id,
            vault_id,
            vault,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
            let conflict = cache
                .item_conflict(vault_id, conflict_id)?
                .ok_or(CliError::Input("conflict not found in synced cache"))?;
            let current = cache
                .latest_item_revision(vault_id, conflict.item_id)?
                .ok_or(CliError::Input("remote item is not in cache"))?;
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let remote = decrypt_cached_item(&vault_key, &current)?;
            let candidate = match conflict.candidate_envelope.clone() {
                Some(envelope) => {
                    let candidate_revision = crate::cache::CachedItemRevision {
                        vault_id,
                        item_id: conflict.item_id,
                        revision: conflict.base_revision + 1,
                        vault_revision: current.vault_revision,
                        key_generation: current.key_generation,
                        author_user_id: conflict.author_user_id,
                        envelope,
                    };
                    Some(decrypt_cached_item(&vault_key, &candidate_revision)?.plaintext)
                }
                None => None,
            };
            if output.is_json() {
                print_json(
                    &serde_json::json!({"conflict": conflict, "remote": remote.plaintext, "candidate": candidate, "candidate_kind": conflict.candidate_kind}),
                )
            } else {
                println!("conflict: {conflict_id}\nremote:");
                render_item_plaintext(OutputMode::Human, conflict.item_id, &remote.plaintext)?;
                if let Some(candidate) = candidate {
                    println!("\ncandidate:");
                    render_item_plaintext(OutputMode::Human, conflict.item_id, &candidate)?;
                } else {
                    println!("\ncandidate: delete");
                }
                Ok(())
            }
        }
        Command::Conflict(ConflictCommand::Resolve {
            conflict_id,
            use_version,
            merge_from,
            fields,
            remove_fields,
            title,
            notes,
            vault_id,
            vault,
        }) => {
            if use_version.is_some() == merge_from.is_some() {
                return Err(CliError::Input("pass exactly one of --use or --merge-from"));
            }
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
            let conflict = cache
                .item_conflict(vault_id, conflict_id)?
                .ok_or(CliError::Input("conflict not found in synced cache"))?;
            let current = cache
                .latest_item_revision(vault_id, conflict.item_id)?
                .ok_or(CliError::Input("remote item is not in cache"))?;
            let (resolution, envelope) = if let Some(choice) = use_version {
                if choice == "remote" {
                    ("remote".to_owned(), None)
                } else if conflict.candidate_kind == "delete" {
                    ("local".to_owned(), None)
                } else {
                    ("local".to_owned(), conflict.candidate_envelope.clone())
                }
            } else {
                if conflict.candidate_kind == "delete" {
                    return Err(CliError::Input(
                        "a delete conflict supports only --use local or --use remote",
                    ));
                }
                let vault_key =
                    unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
                let mut source = if merge_from.as_deref() == Some("remote") {
                    decrypt_cached_item(&vault_key, &current)?
                } else {
                    let envelope = conflict
                        .candidate_envelope
                        .clone()
                        .ok_or(CliError::Input("candidate envelope missing"))?;
                    let candidate_revision = crate::cache::CachedItemRevision {
                        vault_id,
                        item_id: conflict.item_id,
                        revision: conflict.base_revision + 1,
                        vault_revision: current.vault_revision,
                        key_generation: current.key_generation,
                        author_user_id: conflict.author_user_id,
                        envelope,
                    };
                    decrypt_cached_item(&vault_key, &candidate_revision)?
                };
                if let Some(title) = title {
                    source.plaintext.title = title;
                }
                if let Some(notes) = notes {
                    source.plaintext.notes = Some(notes);
                }
                for (name, value) in parse_field_pairs(fields)? {
                    crate::item_plaintext::set_plaintext_field(&mut source.plaintext, &name, value);
                }
                for name in remove_fields {
                    crate::item_plaintext::remove_plaintext_field(&mut source.plaintext, &name);
                }
                (
                    "merge".to_owned(),
                    Some(encrypt_item_plaintext(
                        vault_id,
                        conflict.item_id,
                        current.revision + 1,
                        source.kind,
                        &vault_key,
                        &source.plaintext,
                    )?),
                )
            };
            let client = UmbraHttpClient::new(profile)?;
            let response: ResolveItemConflictResponse = client
                .post(
                    &format!("/api/v1/vaults/{vault_id}/conflicts/{conflict_id}/resolve"),
                    &ResolveItemConflictRequest {
                        protocol_version: PROTOCOL_VERSION,
                        conflict_id,
                        expected_current_revision: current.revision,
                        resolution,
                        envelope,
                    },
                )
                .await?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault_id).await?;
            if output.is_json() {
                print_json(&response)
            } else {
                println!("resolved conflict {conflict_id}");
                Ok(())
            }
        }
        Command::Register {
            server,
            email,
            profile,
            display_name,
            device_name,
        } => {
            set_active_profile(&mut config, profile.clone());
            let password = rpassword::prompt_password("Master password: ")?;
            let confirm = rpassword::prompt_password("Confirm master password: ")?;
            if password != confirm {
                return Err(CliError::Input("passwords do not match"));
            }
            let device_name = match device_name {
                Some(name) => name,
                None => dialoguer::Input::<String>::new()
                    .with_prompt("Device name")
                    .default("CLI device".to_owned())
                    .interact_text()?,
            };
            let device_key = DeviceSigningKey::generate();
            let device_encryption_key = umbra_crypto::generate_user_keypair();
            let account_crypto = crate::crypto_state::NewAccountCrypto::generate(
                &umbra_crypto::MasterPassword::new(password.as_bytes().to_vec()),
            )?;
            let account_public_key = account_crypto.public_key.to_base64url();
            let encrypted_user_private_key =
                serde_json::to_value(&account_crypto.encrypted_private_key)?;
            let user_secret_key = account_crypto.user_secret_key.to_base64url();
            let kdf_params = account_crypto.kdf_params;
            let client = PublicHttpClient::new(&server)?;
            let response = crate::opaque::register(
                &client,
                &email,
                display_name,
                password.as_bytes(),
                &device_name,
                &device_key,
                crate::opaque::AccountRegistrationMaterial {
                    public_key: account_public_key.clone(),
                    encrypted_private_key: encrypted_user_private_key.clone(),
                    device_encryption_public_key: device_encryption_key.public_key.to_base64url(),
                },
            )
            .await?;
            let profile_config = active_profile_mut(&mut config);
            profile_config.server_url = server;
            profile_config.email = Some(email);
            profile_config.user_id = Some(response.user_id);
            profile_config.device_id = Some(response.device_id);
            profile_config.device_private_key = Some(device_key.to_base64url());
            profile_config.device_encryption_private_key =
                Some(device_encryption_key.private_key.to_base64url());
            profile_config.client_public_key = Some(account_public_key);
            profile_config.encrypted_user_private_key = Some(encrypted_user_private_key);
            profile_config.kdf_params = Some(kdf_params);
            profile_config.user_secret_key = Some(user_secret_key);
            profile_config.session_id = None;
            profile_config.legacy_session_token = None;
            save_config(&config)?;
            println!("registered profile: {profile}");
            Ok(())
        }
        Command::Login {
            profile,
            email,
            new_device,
            device_name,
        } => {
            if let Some(profile) = profile {
                set_active_profile(&mut config, profile);
            }
            let profile_snapshot = active_profile(&config)?.clone();
            let email = match email.or(profile_snapshot.email.clone()) {
                Some(email) => email,
                None => dialoguer::Input::<String>::new()
                    .with_prompt("Email")
                    .interact_text()?,
            };
            let password = rpassword::prompt_password("Master password: ")?;
            let client = PublicHttpClient::new(&profile_snapshot.server_url)?;
            if new_device {
                let device_name = match device_name {
                    Some(name) => name,
                    None => dialoguer::Input::<String>::new()
                        .with_prompt("Device name")
                        .default("CLI device".to_owned())
                        .interact_text()?,
                };
                let device_key = DeviceSigningKey::generate();
                let bootstrap_keypair = generate_user_keypair();
                let response = crate::opaque::login_pending_device(
                    &client,
                    &email,
                    password.as_bytes(),
                    device_name,
                    &device_key,
                    bootstrap_keypair.public_key.to_base64url(),
                )
                .await?;
                let pending = response.pending_device.ok_or(CliError::Input(
                    "server did not return pending device details",
                ))?;
                let profile_config = active_profile_mut(&mut config);
                profile_config.email = Some(email);
                profile_config.user_id = Some(response.user_id);
                profile_config.device_id = Some(pending.device_id);
                profile_config.session_id = None;
                profile_config.device_private_key = Some(device_key.to_base64url());
                profile_config.legacy_session_token = response.session_token;
                save_pending_login_crypto_material(profile_config, response.encrypted_private_key);
                profile_config.pending_bootstrap_private_key =
                    Some(bootstrap_keypair.private_key.to_base64url());
                profile_config.pending_approval_code = Some(pending.approval_code.clone());
                save_config(&config)?;
                if output.is_json() {
                    print_json(&pending)
                } else {
                    println!("pending device: {}", pending.device_id);
                    println!("approval code: {}", pending.approval_code);
                    println!("expires at: {}", pending.expires_at);
                    Ok(())
                }
            } else {
                let device_id = profile_snapshot.device_id.ok_or(CliError::Input(
                    "profile has no device id; run `umbra register` first",
                ))?;
                let response =
                    crate::opaque::login(&client, &email, password.as_bytes(), device_id).await?;
                let profile_config = active_profile_mut(&mut config);
                profile_config.email = Some(email);
                profile_config.user_id = Some(response.user_id);
                profile_config.session_id = Some(response.session_id);
                profile_config.legacy_session_token = response.session_token;
                profile_config.pending_bootstrap_private_key = None;
                profile_config.pending_approval_code = None;
                save_config(&config)?;
                println!("logged in: {}", config.active_profile);
                Ok(())
            }
        }
        Command::Unlock {
            vault_id,
            vault,
            all,
            ttl_minutes,
        } => {
            let profile_name = config.active_profile.clone();
            let profile = active_profile(&config)?;
            let user_id = profile.user_id.ok_or(CliError::Input(
                "profile has no user id; run `umbra login` first",
            ))?;
            let device_id = profile.device_id.ok_or(CliError::Input(
                "profile has no device id; run `umbra register` first",
            ))?;
            if ttl_minutes <= 0 {
                return Err(CliError::Input("ttl-minutes must be greater than zero"));
            }

            let mut cache = crate::cache::LocalCache::open(&profile_name)?;
            let vault_ids =
                selected_unlock_vaults(profile, &cache, vault_id, vault.as_deref(), all)?;
            for vault_id in vault_ids.iter().copied() {
                crate::sync::ensure_vault_synced(
                    profile,
                    &mut cache,
                    vault_id,
                    crate::sync::SyncMode::IfChanged,
                )
                .await?;
            }

            let device_private_key = UserPrivateKey::from_base64url(
                profile
                    .device_encryption_private_key
                    .as_deref()
                    .ok_or(CliError::Input(
                        "profile has no device encryption key; re-enroll this device",
                    ))?,
            )?;
            let mut vault_keys = BTreeMap::new();
            for vault_id in vault_ids {
                let wrapping = cache
                    .latest_device_key_wrapping(vault_id, user_id, device_id)?
                    .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
                let envelope: VaultKeyWrappingEnvelopeV1 =
                    serde_json::from_value(wrapping.envelope)?;
                let aad = AadV1::device_vault_key_wrapping(
                    vault_id.to_string(),
                    device_id.to_string(),
                    wrapping.key_generation,
                );
                let vault_key = unwrap_vault_key(&device_private_key, &aad, &envelope)?;
                vault_keys.insert(vault_id, vault_key);
            }

            let state = crate::unlock_store::UnlockedLocalState::new(
                profile_name.clone(),
                user_id,
                device_id,
                chrono::Utc::now() + chrono::Duration::minutes(ttl_minutes),
                device_private_key,
                vault_keys,
            );
            crate::unlock_store::UnlockStore::open(&profile_name, profile.device_id)
                .save(&state)?;
            print_json(&crate::unlock_store::UnlockStatus {
                unlocked: true,
                profile: profile_name,
                expires_at: Some(state.expires_at),
                vault_count: state.vault_keys.len(),
            })
        }
        Command::Lock => {
            let profile_name = config.active_profile.clone();
            let profile = active_profile(&config)?;
            crate::unlock_store::UnlockStore::open(&profile_name, profile.device_id).clear()?;
            println!("locked");
            Ok(())
        }
        Command::Status => {
            let profile_name = config.active_profile.clone();
            let profile = active_profile(&config)?;
            let status = crate::unlock_store::UnlockStore::open(&profile_name, profile.device_id)
                .status()?;
            render_unlock_status(output, &status)
        }
        Command::Auth(AuthCommand::Token(TokenCommand::Set { server_url, token })) => {
            let profile = active_profile_mut(&mut config);
            profile.server_url = server_url;
            profile.legacy_session_token = Some(token);
            profile.session_id = None;
            save_config(&config)?;
            println!("token saved");
            Ok(())
        }
        Command::Cache(CacheCommand::Status) => {
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let status = cache.status()?;
            render_cache_status(output, &status)
        }
        Command::Cache(CacheCommand::Clear) => {
            crate::cache::LocalCache::clear_persistent(&config.active_profile)?;
            println!("encrypted cache cleared");
            Ok(())
        }
        Command::EmergencyKit(EmergencyKitCommand::Export { output }) => {
            let profile = active_profile(&config)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let anchors = cache.trusted_checkpoint_devices()?;
            let trust_bundle = if anchors.is_empty() {
                None
            } else {
                let password = rpassword::prompt_password("Master password: ")?;
                let unlocked = crate::crypto_state::load_unlocked_profile(
                    profile,
                    &MasterPassword::new(password.into_bytes()),
                )?;
                Some(authenticated_checkpoint_trust_bundle(&unlocked, &anchors)?)
            };
            let encoded = emergency_kit_json_from_profile_with_trust_bundle(profile, trust_bundle)?;
            if let Some(path) = output {
                std::fs::write(&path, encoded)?;
                println!("emergency kit written: {}", path.display());
                Ok(())
            } else {
                println!("{encoded}");
                Ok(())
            }
        }
        Command::Profile(ProfileCommand::List) => {
            for (name, profile) in &config.profiles {
                let marker = if name == &config.active_profile {
                    "*"
                } else {
                    " "
                };
                let email = profile.email.as_deref().unwrap_or("-");
                println!("{marker} {name}\t{email}\t{}", profile.server_url);
            }
            Ok(())
        }
        Command::Profile(ProfileCommand::Use { name }) => {
            set_active_profile(&mut config, name.clone());
            save_config(&config)?;
            println!("active profile: {name}");
            Ok(())
        }
        Command::Device(DeviceCommand::List) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let devices: Vec<DeviceResponse> = client.get("/api/v1/devices").await?;
            render_devices(output, &devices)
        }
        Command::Device(DeviceCommand::Pending) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let devices: Vec<PendingDeviceSummary> = client.get("/api/v1/devices/pending").await?;
            render_pending_devices(output, &devices)
        }
        Command::Device(DeviceCommand::Approve {
            approval_code,
            device_id,
            bootstrap_bundle_json,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let pending: PendingDeviceSummary = client
                .post(
                    "/api/v1/devices/approval-lookup",
                    &ApprovalLookupRequest {
                        protocol_version: PROTOCOL_VERSION,
                        approval_code: approval_code.clone(),
                    },
                )
                .await?;
            if let Some(device_id) = device_id
                && device_id != pending.device_id
            {
                return Err(CliError::Input("approval code belongs to another device"));
            }
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            crate::sync::record_local_trust_anchor(profile, &cache)?;
            let devices: Vec<DeviceResponse> = client.get("/api/v1/devices").await?;
            let pending_device = devices
                .iter()
                .find(|device| device.device_id == pending.device_id)
                .ok_or(CliError::Input(
                    "pending device is missing from authenticated device list",
                ))?;
            let pending_anchor = checkpoint_anchor_from_device(pending_device)?;
            let mut trusted_checkpoint_devices = cache.trusted_checkpoint_devices()?;
            if !trusted_checkpoint_devices
                .iter()
                .any(|device| device.device_id == pending_anchor.device_id)
            {
                trusted_checkpoint_devices.push(pending_anchor.clone());
            }
            let bootstrap_bundle = if let Some(raw) = bootstrap_bundle_json {
                serde_json::from_str(&raw)?
            } else {
                let recipient = UserPublicKey::from_base64url(&pending.bootstrap_public_key)?;
                let bundle =
                    device_bootstrap_bundle_from_profile(profile, &trusted_checkpoint_devices)?;
                let envelope = encrypt_device_bootstrap_bundle(
                    &recipient,
                    AadV1::device_bootstrap(pending.device_id.to_string()),
                    &bundle,
                )?;
                serde_json::to_value(envelope)?
            };
            let approved: DeviceResponse = client
                .post(
                    &format!("/api/v1/devices/{}/approve", pending.device_id),
                    &ApproveDeviceRequest {
                        protocol_version: PROTOCOL_VERSION,
                        approval_code,
                        bootstrap_bundle,
                    },
                )
                .await?;
            let approved_anchor = checkpoint_anchor_from_device(&approved)?;
            if approved_anchor != pending_anchor {
                return Err(CliError::Input(
                    "approved device signing key changed during approval",
                ));
            }
            cache.record_trusted_checkpoint_device(&approved_anchor)?;
            if output.is_json() {
                print_json(&approved)
            } else {
                println!("approved device: {}", approved.device_id);
                Ok(())
            }
        }
        Command::Device(DeviceCommand::Revoke { device_id }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let revoked: DeviceResponse = client
                .post(&format!("/api/v1/devices/{device_id}/revoke"), &Value::Null)
                .await?;
            if output.is_json() {
                print_json(&revoked)
            } else {
                println!("revoked device: {}", revoked.device_id);
                Ok(())
            }
        }
        Command::Device(DeviceCommand::Bootstrap { device_id }) => {
            let profile = active_profile_mut(&mut config);
            let device_id = device_id
                .or(profile.device_id)
                .ok_or(CliError::Input("profile has no pending device id"))?;
            let bootstrap_private_key = profile
                .pending_bootstrap_private_key
                .as_deref()
                .ok_or(CliError::Input("profile has no pending bootstrap key"))?;
            let client = UmbraHttpClient::new(profile)?;
            let response: DeviceBootstrapResponse = client
                .get(&format!("/api/v1/devices/{device_id}/bootstrap"))
                .await?;
            let Some(bundle_value) = response.bootstrap_bundle.as_ref() else {
                return Err(CliError::Input("device has no bootstrap bundle yet"));
            };
            let envelope: DeviceBootstrapEnvelopeV1 = serde_json::from_value(bundle_value.clone())?;
            let private_key = UserPrivateKey::from_base64url(bootstrap_private_key)?;
            let aad = AadV1::device_bootstrap(device_id.to_string());
            let bundle = decrypt_device_bootstrap_bundle(&private_key, &aad, &envelope)?;
            let trusted_checkpoint_devices = bundle
                .trusted_checkpoint_devices
                .iter()
                .map(checkpoint_anchor_from_bootstrap)
                .collect::<Result<Vec<_>, _>>()?;
            profile.kdf_params = Some(bundle.kdf_params);
            profile.encrypted_user_private_key =
                Some(serde_json::to_value(bundle.encrypted_user_private_key)?);
            profile.client_public_key = Some(bundle.account_public_key);
            profile.user_secret_key = Some(bundle.user_secret_key);
            profile.default_vault_id = bundle
                .default_vault_id
                .map(|id| Uuid::parse_str(&id))
                .transpose()
                .map_err(|_| CliError::Input("invalid default vault id in bootstrap bundle"))?;
            profile.pending_bootstrap_private_key = None;
            profile.pending_approval_code = None;
            save_config(&config)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            for trusted_device in trusted_checkpoint_devices {
                cache.record_trusted_checkpoint_device(&trusted_device)?;
            }
            if output.is_json() {
                print_json(&response)
            } else {
                println!("device bootstrapped: {device_id}");
                Ok(())
            }
        }
        Command::Device(DeviceCommand::Recover {
            device_id,
            emergency_kit,
        }) => {
            let profile = active_profile_mut(&mut config);
            let device_id = device_id
                .or(profile.device_id)
                .ok_or(CliError::Input("profile has no pending device id"))?;
            let emergency_kit = match emergency_kit {
                Some(path) => read_emergency_kit(&path)?,
                None => {
                    return Err(CliError::Input(
                        "pass --emergency-kit <path> for clean-device recovery",
                    ));
                }
            };
            let client = UmbraHttpClient::new(profile)?;
            let challenge: RecoveryChallengeStartResponse = client
                .post(
                    &format!("/api/v1/devices/{device_id}/recovery-challenge"),
                    &RecoveryChallengeStartRequest {
                        protocol_version: PROTOCOL_VERSION,
                        device_id,
                    },
                )
                .await?;
            let password = rpassword::prompt_password("Master password: ")?;
            let master_password = MasterPassword::new(password.into_bytes());
            let unlocked = crate::crypto_state::unlock_profile_with_emergency_kit(
                profile,
                &master_password,
                &emergency_kit,
            )?;
            let recovered_checkpoint_anchors =
                checkpoint_anchors_from_emergency_kit(&unlocked, &emergency_kit)?;
            let envelope: RecoveryChallengeEnvelopeV1 =
                serde_json::from_value(challenge.encrypted_challenge)?;
            let aad = AadV1::recovery_challenge(
                device_id.to_string(),
                challenge.challenge_id.to_string(),
            );
            let plaintext = decrypt_recovery_challenge(&unlocked.private_key, &aad, &envelope)?;
            let challenge_response =
                String::from_utf8(plaintext).map_err(|_| CliError::Input("invalid challenge"))?;
            let recovered: RecoverTrustResponse = client
                .post(
                    &format!("/api/v1/devices/{device_id}/recover-trust"),
                    &RecoverTrustRequest {
                        protocol_version: PROTOCOL_VERSION,
                        challenge_id: challenge.challenge_id,
                        challenge_response,
                    },
                )
                .await?;
            apply_recovered_emergency_kit_material(profile, &emergency_kit)?;
            save_config(&config)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            record_checkpoint_trust_anchors(&cache, &recovered_checkpoint_anchors)?;
            if output.is_json() {
                print_json(&recovered)
            } else {
                println!("recovered device trust: {}", recovered.device_id);
                Ok(())
            }
        }
        Command::Org(OrgCommand::List) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let orgs: Vec<OrgResponse> = client.get("/api/v1/orgs").await?;
            render_orgs(output, &orgs)
        }
        Command::Org(OrgCommand::Create { name }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let org: OrgResponse = client
                .post(
                    "/api/v1/orgs",
                    &CreateOrgRequest {
                        protocol_version: PROTOCOL_VERSION,
                        name,
                    },
                )
                .await?;
            render_org_created(output, &org)
        }
        Command::Org(OrgCommand::Members { org_id }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let members: Vec<OrgMemberResponse> = client
                .get(&format!("/api/v1/orgs/{org_id}/members"))
                .await?;
            render_org_members(output, &members)
        }
        Command::Org(OrgCommand::AddMember {
            org_id,
            email,
            user_id,
            role,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let looked_up = match email.as_deref() {
                Some(email) => Some(lookup_user_by_email(&client, email).await?.user_id),
                None => None,
            };
            let target_user_id = resolve_target_user_id(user_id, looked_up, email.as_deref())?;
            let member: OrgMemberResponse = client
                .post(
                    &format!("/api/v1/orgs/{org_id}/members"),
                    &AddOrgMemberRequest {
                        protocol_version: PROTOCOL_VERSION,
                        user_id: target_user_id,
                        role,
                    },
                )
                .await?;
            render_org_member_added(output, &member)
        }
        Command::Crypto(CryptoCommand::RotationStatus { vault_id, vault }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let client = UmbraHttpClient::new(profile)?;
            let status: RotationStatusResponse = client
                .get(&format!("/api/v1/vaults/{vault_id}/rotation-status"))
                .await?;
            render_rotation_status(output, &status)
        }
        Command::Crypto(CryptoCommand::RotateVaultKey {
            vault_id,
            vault,
            dry_run,
            force,
            yes,
        }) => {
            let profile_name = config.active_profile.clone();
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let device_id = profile.device_id.ok_or(CliError::Input(
                "profile has no device id; run `umbra login` first",
            ))?;
            let client = UmbraHttpClient::new(profile)?;
            let mut cache = crate::cache::LocalCache::open(&profile_name)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::record_local_trust_anchor(profile, &cache)?;
            if cache.is_sync_unsafe(vault_id)? {
                return Err(cache.integrity_error(vault_id)?);
            }
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
            let status: RotationStatusResponse = client
                .get(&format!("/api/v1/vaults/{vault_id}/rotation-status"))
                .await?;
            if !status.needs_key_rotation && !force {
                return Err(CliError::Input(
                    "vault does not require rotation; pass --force to rotate anyway",
                ));
            }
            if output.is_json() && !dry_run && !yes {
                return Err(CliError::Input(
                    "pass --yes to rotate vault key in JSON mode",
                ));
            }
            if !output.is_json()
                && !dry_run
                && !yes
                && !dialoguer::Confirm::new()
                    .with_prompt("Rotate this vault key and reencrypt all cached items?")
                    .default(false)
                    .interact()?
            {
                return Err(CliError::Input("vault key rotation cancelled"));
            }

            let full_sync: SyncResponse = client
                .post(
                    "/api/v1/sync",
                    &SyncRequest {
                        protocol_version: SYNC_INTEGRITY_PROTOCOL_VERSION,
                        device_id,
                        vaults: vec![VaultSyncCursor {
                            vault_id,
                            since_vault_revision: 0,
                        }],
                    },
                )
                .await?;
            if full_sync.protocol_version != SYNC_INTEGRITY_PROTOCOL_VERSION {
                cache.quarantine_transport_failure(
                    vault_id,
                    0,
                    &format!("protocol-version-{}", full_sync.protocol_version),
                    "protocol_downgrade",
                )?;
                return Err(cache.integrity_error(vault_id)?);
            }
            let matching_full_changes = full_sync
                .vaults
                .iter()
                .filter(|changes| changes.vault_id == vault_id)
                .collect::<Vec<_>>();
            let [full_changes] = matching_full_changes.as_slice() else {
                let code = if matching_full_changes.is_empty() {
                    "missing_vault_response"
                } else {
                    "duplicate_vault_response"
                };
                cache.quarantine_transport_failure(vault_id, 0, "missing", code)?;
                return Err(cache.integrity_error(vault_id)?);
            };
            let snapshot_item_ids = full_changes
                .items
                .iter()
                .map(|item| item.item_id)
                .collect::<Vec<_>>();
            let full_checkpoints = full_sync
                .checkpoints
                .iter()
                .filter(|checkpoint| checkpoint.vault_id == vault_id)
                .cloned()
                .collect::<Vec<_>>();
            cache.verify_and_record_checkpoints(full_changes, &full_checkpoints)?;
            let members: Vec<VaultMemberResponse> = client
                .get(&format!("/api/v1/vaults/{vault_id}/members"))
                .await?;
            let current_revisions = cache.list_latest_item_revisions(vault_id)?;
            let old_vault_key = unlock_vault_key(&profile_name, profile, &cache, vault_id)?;
            let new_vault_key = generate_vault_key();
            let request = build_rotation_request(
                vault_id,
                status.current_key_generation,
                &old_vault_key,
                &new_vault_key,
                &members,
                &current_revisions,
                RotationCacheSnapshot::full_vault(snapshot_item_ids),
            )?;
            let summary = RotationPlanSummary {
                vault_id,
                from_generation: request.from_generation,
                to_generation: request.to_generation,
                member_wrapping_count: request.new_wrappings.len(),
                item_revision_count: request.reencrypted_revisions.len(),
                dry_run,
            };
            if dry_run {
                return render_rotation_dry_run(output, &summary);
            }

            let completed: RotationStatusResponse = client
                .post(&format!("/api/v1/vaults/{vault_id}/rotate-key"), &request)
                .await?;
            save_rotated_vault_key_to_unlock_store(
                &profile_name,
                profile,
                vault_id,
                new_vault_key.clone(),
            )?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault_id).await?;
            refresh_cached_vault_metadata(&client, &cache, vault_id).await?;
            render_rotation_complete(output, &completed, &summary)
        }
        Command::Vault(VaultCommand::List) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let vaults: Vec<VaultResponse> = client.get("/api/v1/vaults").await?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            for vault in &vaults {
                cache.upsert_vault(vault)?;
            }
            render_vaults(output, &vaults)
        }
        Command::Vault(VaultCommand::Create {
            name,
            org_id,
            wrapping_json,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let name = match name {
                Some(name) => name,
                None => dialoguer::Input::<String>::new()
                    .with_prompt("Vault name")
                    .interact_text()?,
            };
            let kind = if org_id.is_some() {
                VaultKind::Org
            } else {
                VaultKind::Personal
            };
            let requested_vault_id = Uuid::new_v4();
            let initial_key_wrapping = match wrapping_json {
                Some(value) => serde_json::from_str(&value)?,
                None => {
                    let device_id = profile.device_id.ok_or(CliError::Input(
                        "profile has no device id; run `umbra register` first",
                    ))?;
                    let private_key = UserPrivateKey::from_base64url(
                        profile
                            .device_encryption_private_key
                            .as_deref()
                            .ok_or(CliError::Input(
                                "profile has no device encryption key; re-enroll this device",
                            ))?,
                    )?;
                    let public_key = private_key.public_key();
                    let vault_key = generate_vault_key();
                    let aad = AadV1::device_vault_key_wrapping(
                        requested_vault_id.to_string(),
                        device_id.to_string(),
                        1,
                    );
                    let wrapping = wrap_vault_key_for_user(&public_key, &vault_key, aad)?;
                    serde_json::to_value(wrapping)?
                }
            };
            let vault: VaultResponse = if let Some(org_id) = org_id {
                client
                    .post(
                        &vault_create_path(Some(org_id)),
                        &CreateOrgVaultRequest {
                            protocol_version: DEVICE_SCOPED_WRAPPING_PROTOCOL_VERSION,
                            vault_id: Some(requested_vault_id),
                            name,
                            kind,
                            initial_key_wrapping,
                        },
                    )
                    .await?
            } else {
                client
                    .post(
                        &vault_create_path(None),
                        &CreateVaultRequest {
                            protocol_version: DEVICE_SCOPED_WRAPPING_PROTOCOL_VERSION,
                            vault_id: Some(requested_vault_id),
                            name,
                            kind,
                            initial_key_wrapping,
                        },
                    )
                    .await?
            };
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            cache.upsert_vault(&vault)?;
            let profile_config = active_profile_mut(&mut config);
            if profile_config.default_vault_id.is_none() {
                profile_config.default_vault_id = Some(vault.vault_id);
                save_config(&config)?;
            }
            let profile = active_profile(&config)?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault.vault_id)
                .await?;
            render_vault_created(output, &vault)
        }
        Command::Vault(VaultCommand::Members { vault_id, vault }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let client = UmbraHttpClient::new(profile)?;
            let members: Vec<VaultMemberResponse> = client
                .get(&format!("/api/v1/vaults/{vault_id}/members"))
                .await?;
            render_vault_members(output, &members)
        }
        Command::Vault(VaultCommand::Invite {
            vault_id,
            vault,
            email,
            role,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let client = UmbraHttpClient::new(profile)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::IfChanged,
            )
            .await?;
            let user = lookup_user_by_email(&client, &email).await?;
            let target_public_key = UserPublicKey::from_base64url(&user.public_key)?;
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let vault_key_wrapping =
                wrap_vault_key_for_member(&target_public_key, &vault_key, vault_id)?;
            let invite: InviteResponse = client
                .post(
                    &format!("/api/v1/vaults/{vault_id}/invites"),
                    &InviteMemberRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        email,
                        role,
                        vault_key_wrapping,
                    },
                )
                .await?;
            render_invite_created(output, &invite)
        }
        Command::Vault(VaultCommand::AddMember {
            vault_id,
            vault,
            email,
            user_id,
            role,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let client = UmbraHttpClient::new(profile)?;
            let looked_up = match email.as_deref() {
                Some(email) => Some(lookup_user_by_email(&client, email).await?),
                None => None,
            };
            let target_user_id = resolve_target_user_id(
                user_id,
                looked_up.as_ref().map(|user| user.user_id),
                email.as_deref(),
            )?;
            let target_public_key = match looked_up {
                Some(user) => UserPublicKey::from_base64url(&user.public_key)?,
                None => {
                    return Err(CliError::Input(
                        "vault add-member requires --email so the CLI can fetch the target public key",
                    ));
                }
            };
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let vault_key_wrapping =
                wrap_vault_key_for_member(&target_public_key, &vault_key, vault_id)?;
            let member: VaultMemberResponse = client
                .post(
                    &format!("/api/v1/vaults/{vault_id}/members"),
                    &AddVaultMemberRequest {
                        protocol_version: PROTOCOL_VERSION,
                        user_id: target_user_id,
                        role,
                        vault_key_wrapping,
                    },
                )
                .await?;
            render_vault_member_added(output, &member)
        }
        Command::Vault(VaultCommand::RemoveMember {
            vault_id,
            vault,
            user_id,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let client = UmbraHttpClient::new(profile)?;
            client
                .delete(&format!("/api/v1/vaults/{vault_id}/members/{user_id}"))
                .await?;
            if output.is_json() {
                print_json(&serde_json::json!({
                    "vault_id": vault_id,
                    "user_id": user_id,
                    "removed": true
                }))
            } else {
                crate::output::print_kv(&[
                    ("vault_id", vault_id.to_string()),
                    ("removed user", user_id.to_string()),
                    ("key rotation needed", "yes".to_owned()),
                ]);
                Ok(())
            }
        }
        Command::Invite(InviteCommand::List) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let invites: Vec<PendingInviteResponse> = client.get("/api/v1/invites").await?;
            render_pending_invites(output, &invites)
        }
        Command::Invite(InviteCommand::Accept { invite_id }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let device_id = profile.device_id.ok_or(CliError::Input(
                "profile has no device id; run `umbra login` first",
            ))?;
            let client = UmbraHttpClient::new(profile)?;
            let member: VaultMemberResponse = client
                .post(
                    &format!("/api/v1/invites/{invite_id}/accept"),
                    &AcceptInviteRequest {
                        protocol_version: PROTOCOL_VERSION,
                        invite_id,
                        device_id,
                    },
                )
                .await?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            refresh_cached_vault_metadata(&client, &cache, member.vault_id).await?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                member.vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
            render_invite_accepted(output, &member)
        }
        Command::Invite(InviteCommand::Reject { invite_id }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let invite: InviteResponse = client
                .post(
                    &format!("/api/v1/invites/{invite_id}/reject"),
                    &RejectInviteRequest {
                        protocol_version: PROTOCOL_VERSION,
                        invite_id,
                    },
                )
                .await?;
            render_invite_rejected(output, &invite)
        }
        Command::Item(ItemCommand::List {
            vault_id,
            vault,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let mode = if offline {
                crate::sync::SyncMode::Offline
            } else {
                require_login(profile)?;
                crate::sync::SyncMode::IfChanged
            };
            let sync_outcome =
                crate::sync::ensure_vault_synced(profile, &mut cache, vault_id, mode).await?;
            let _ = (
                sync_outcome.synced,
                sync_outcome.latest_vault_revision,
                sync_outcome.latest_access_revision,
            );
            if output.is_json() {
                print_json(&cache.list_latest_item_revisions(vault_id)?)
            } else {
                let vault_key =
                    unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
                let items = decrypted_listed_items(&cache, &vault_key, vault_id)?;
                render_item_list(output, &items)
            }
        }
        Command::Item(ItemCommand::Get {
            vault_id,
            vault,
            item_id,
            title,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let mode = if offline {
                crate::sync::SyncMode::Offline
            } else {
                require_login(profile)?;
                crate::sync::SyncMode::IfChanged
            };
            let sync_outcome =
                crate::sync::ensure_vault_synced(profile, &mut cache, vault_id, mode).await?;
            let _ = (
                sync_outcome.synced,
                sync_outcome.latest_vault_revision,
                sync_outcome.latest_access_revision,
            );
            let selection = select_cached_item_revision_before_unlock_for_output(
                &cache,
                vault_id,
                item_id,
                title.as_deref(),
                output,
            )?;
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let revision = match selection {
                ItemSelectionNeed::Selected(revision) => revision,
                ItemSelectionNeed::NeedsTitleDecrypt => select_cached_item_revision_by_title(
                    &cache,
                    &vault_key,
                    vault_id,
                    title.as_deref().expect("title selector was validated"),
                )?,
                ItemSelectionNeed::NeedsInteractiveDecrypt => {
                    select_cached_item_revision_interactively(&cache, &vault_key, vault_id)?
                }
            };
            let item = decrypt_cached_item(&vault_key, &revision)?;
            render_item_plaintext(output, revision.item_id, &item.plaintext)
        }
        Command::Item(ItemCommand::Delete {
            vault_id,
            vault,
            item_id,
            title,
            yes,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            if output.is_json() && !yes {
                return Err(CliError::Input("pass --yes to delete item in JSON mode"));
            }
            let client = UmbraHttpClient::new(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::IfChanged,
            )
            .await?;
            let selection = select_cached_item_revision_before_unlock_for_output(
                &cache,
                vault_id,
                item_id,
                title.as_deref(),
                output,
            )?;
            let revision = match selection {
                ItemSelectionNeed::Selected(revision) => revision,
                ItemSelectionNeed::NeedsTitleDecrypt => {
                    let vault_key =
                        unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
                    select_cached_item_revision_by_title(
                        &cache,
                        &vault_key,
                        vault_id,
                        title.as_deref().expect("title selector was validated"),
                    )?
                }
                ItemSelectionNeed::NeedsInteractiveDecrypt => {
                    let vault_key =
                        unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
                    select_cached_item_revision_interactively(&cache, &vault_key, vault_id)?
                }
            };

            if !output.is_json()
                && !yes
                && !dialoguer::Confirm::new()
                    .with_prompt("Delete this item?")
                    .default(false)
                    .interact()?
            {
                return Err(CliError::Input("item deletion cancelled"));
            }

            client
                .delete_json(
                    &format!("/api/v1/vaults/{vault_id}/items/{}", revision.item_id),
                    &DeleteItemRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        item_id: revision.item_id,
                        expected_revision: revision.revision,
                    },
                )
                .await?;
            cache.delete_item(vault_id, revision.item_id)?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault_id).await?;
            render_item_deleted(output, vault_id, revision.item_id, revision.revision)
        }
        Command::Item(ItemCommand::Create {
            vault_id,
            vault,
            kind,
            title,
            fields,
            notes,
            tags,
            envelope_json,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::IfChanged,
            )
            .await?;
            let (item_id, envelope) = match envelope_json {
                Some(envelope_json) => (None, serde_json::from_str(&envelope_json)?),
                None => {
                    let vault_key =
                        unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
                    let item_id = Uuid::new_v4();
                    let kind_name = item_kind_name(&kind);
                    let title = title.unwrap_or_else(|| kind_name.clone());
                    let plaintext = crate::item_plaintext::build_item(
                        &title,
                        parse_field_pairs(fields)?,
                        notes,
                        tags,
                    );
                    (
                        Some(item_id),
                        encrypt_item_plaintext(
                            vault_id, item_id, 1, kind_name, &vault_key, &plaintext,
                        )?,
                    )
                }
            };
            let response: ItemRevisionResponse = client
                .post(
                    &format!("/api/v1/vaults/{vault_id}/items"),
                    &CreateItemRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        item_id,
                        kind,
                        envelope,
                    },
                )
                .await?;
            cache.upsert_item_revision(&response)?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault_id).await?;
            render_item_revision_created(output, "created item", &response)
        }
        Command::Item(ItemCommand::Update {
            vault_id,
            item_id,
            expected_revision,
            envelope_json,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::IfChanged,
            )
            .await?;
            let response: ItemRevisionResponse = client
                .put(
                    &format!("/api/v1/vaults/{vault_id}/items/{item_id}"),
                    &UpdateItemRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        item_id,
                        expected_revision,
                        envelope: serde_json::from_str(&envelope_json)?,
                    },
                )
                .await?;
            cache.upsert_item_revision(&response)?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault_id).await?;
            print_json(&response)
        }
        Command::Secret(SecretCommand::Set {
            project_env,
            key,
            value,
            vault_id,
            vault,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let value = match value {
                Some(value) => value,
                None => rpassword::prompt_password("Value: ")?,
            };
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::IfChanged,
            )
            .await?;
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let kind = ItemKind::EnvBundle;
            let kind_name = item_kind_name(&kind);
            let existing_bundle = find_secret_bundle(&cache, &vault_key, vault_id, &project_env)?;

            let response: ItemRevisionResponse =
                if let Some((revision, mut plaintext)) = existing_bundle {
                    crate::item_plaintext::set_plaintext_field(&mut plaintext, &key, value);
                    let next_revision = revision.revision + 1;
                    let envelope = encrypt_item_plaintext(
                        vault_id,
                        revision.item_id,
                        next_revision,
                        kind_name,
                        &vault_key,
                        &plaintext,
                    )?;
                    client
                        .put(
                            &format!("/api/v1/vaults/{vault_id}/items/{}", revision.item_id),
                            &UpdateItemRequest {
                                protocol_version: PROTOCOL_VERSION,
                                vault_id,
                                item_id: revision.item_id,
                                expected_revision: revision.revision,
                                envelope,
                            },
                        )
                        .await?
                } else {
                    let item_id = Uuid::new_v4();
                    let plaintext =
                        crate::item_plaintext::build_secret_bundle(&project_env, &key, &value);
                    let envelope = encrypt_item_plaintext(
                        vault_id, item_id, 1, kind_name, &vault_key, &plaintext,
                    )?;
                    client
                        .post(
                            &format!("/api/v1/vaults/{vault_id}/items"),
                            &CreateItemRequest {
                                protocol_version: PROTOCOL_VERSION,
                                vault_id,
                                item_id: Some(item_id),
                                kind,
                                envelope,
                            },
                        )
                        .await?
                };
            cache.upsert_item_revision(&response)?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault_id).await?;
            render_item_revision_created(output, "saved secret", &response)
        }
        Command::Secret(SecretCommand::List {
            project_env,
            vault_id,
            vault,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let mode = if offline {
                crate::sync::SyncMode::Offline
            } else {
                require_login(profile)?;
                crate::sync::SyncMode::IfChanged
            };
            let sync_outcome =
                crate::sync::ensure_vault_synced(profile, &mut cache, vault_id, mode).await?;
            let _ = (
                sync_outcome.synced,
                sync_outcome.latest_vault_revision,
                sync_outcome.latest_access_revision,
            );
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let Some((_revision, plaintext)) =
                find_secret_bundle(&cache, &vault_key, vault_id, &project_env)?
            else {
                return Err(CliError::Input("secret bundle not found"));
            };
            render_secret_list(output, &plaintext)
        }
        Command::Secret(SecretCommand::Get {
            project_env,
            key,
            vault_id,
            vault,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            let mode = if offline {
                crate::sync::SyncMode::Offline
            } else {
                require_login(profile)?;
                crate::sync::SyncMode::IfChanged
            };
            let sync_outcome =
                crate::sync::ensure_vault_synced(profile, &mut cache, vault_id, mode).await?;
            let _ = (
                sync_outcome.synced,
                sync_outcome.latest_vault_revision,
                sync_outcome.latest_access_revision,
            );
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let Some((_revision, plaintext)) =
                find_secret_bundle(&cache, &vault_key, vault_id, &project_env)?
            else {
                return Err(CliError::Input("secret bundle not found"));
            };
            let key = resolve_secret_key_for_output(key, &plaintext, output)?;
            if let Some(field) = plaintext.fields.iter().find(|field| field.name == key) {
                println!("{}", field.value);
                return Ok(());
            }
            Err(CliError::Input("secret key not found"))
        }
        Command::Secret(SecretCommand::Rm {
            project_env,
            key,
            vault_id,
            vault,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::IfChanged,
            )
            .await?;
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let Some((revision, mut plaintext)) =
                find_secret_bundle(&cache, &vault_key, vault_id, &project_env)?
            else {
                return Err(CliError::Input("secret bundle not found"));
            };
            let key = resolve_secret_key_for_output(key, &plaintext, output)?;
            if !crate::item_plaintext::remove_plaintext_field(&mut plaintext, &key) {
                return Err(CliError::Input("secret key not found"));
            }

            let kind = ItemKind::EnvBundle;
            let kind_name = item_kind_name(&kind);
            let next_revision = revision.revision + 1;
            let envelope = encrypt_item_plaintext(
                vault_id,
                revision.item_id,
                next_revision,
                kind_name,
                &vault_key,
                &plaintext,
            )?;
            let response: ItemRevisionResponse = client
                .put(
                    &format!("/api/v1/vaults/{vault_id}/items/{}", revision.item_id),
                    &UpdateItemRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        item_id: revision.item_id,
                        expected_revision: revision.revision,
                        envelope,
                    },
                )
                .await?;
            cache.upsert_item_revision(&response)?;
            crate::sync::publish_checkpoint_after_mutation(profile, &mut cache, vault_id).await?;
            if output.is_json() {
                print_json(&response)
            } else {
                println!("removed {key} from {project_env}");
                Ok(())
            }
        }
        Command::Env(EnvCommand::Get {
            project_env,
            vault_id,
            vault,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let plaintext = load_env_bundle_for_command(
                &config,
                profile,
                output,
                &project_env,
                vault_id,
                vault.as_deref(),
                offline,
            )
            .await?;
            if output.is_json() {
                print_json(&serde_json::json!({
                    "project_env": project_env,
                    "variables": env_variables_json(&plaintext),
                }))
            } else {
                let dotenv = crate::item_plaintext::render_dotenv(&plaintext);
                print!("{dotenv}");
                Ok(())
            }
        }
        Command::Env(EnvCommand::Inject {
            project_env,
            vault_id,
            vault,
            output: output_path,
            offline,
            yes,
        }) => {
            let profile = active_profile(&config)?;
            let plaintext = load_env_bundle_for_command(
                &config,
                profile,
                output,
                &project_env,
                vault_id,
                vault.as_deref(),
                offline,
            )
            .await?;
            let dotenv = crate::item_plaintext::render_dotenv(&plaintext);
            write_env_file(&output_path, &dotenv, yes)?;
            if output.is_json() {
                print_json(&serde_json::json!({
                    "project_env": project_env,
                    "output": output_path,
                    "written": true
                }))
            } else {
                crate::output::print_kv(&[
                    ("project_env", project_env),
                    ("output", output_path.display().to_string()),
                    ("written", "true".to_owned()),
                ]);
                Ok(())
            }
        }
        Command::Run {
            project_env,
            vault_id,
            vault,
            offline,
            command,
        } => {
            if command.is_empty() {
                return Err(CliError::Input("run requires a command after --"));
            }
            let profile = active_profile(&config)?;
            let plaintext = load_env_bundle_for_command(
                &config,
                profile,
                output,
                &project_env,
                vault_id,
                vault.as_deref(),
                offline,
            )
            .await?;
            let env_pairs = crate::item_plaintext::env_pairs(&plaintext);
            let mut child = build_env_command(&command, env_pairs)?;
            let status = child.status()?;
            if status.success() {
                Ok(())
            } else {
                Err(CliError::ProcessExit(status))
            }
        }
        Command::Sync(SyncCommand::Run {
            vault_id,
            vault,
            since_vault_revision,
            force_full,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let device_id = profile.device_id.ok_or(CliError::Input(
                "profile has no device id; run `umbra login` first",
            ))?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id =
                resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
            crate::sync::record_local_trust_anchor(profile, &cache)?;
            if cache.is_sync_unsafe(vault_id)? {
                return Err(cache.integrity_error(vault_id)?);
            }
            let verified_revision = cache
                .integrity_state(vault_id)?
                .verified_head
                .map(|head| head.checkpoint.vault_revision)
                .unwrap_or(0);
            let since_vault_revision = if force_full {
                0
            } else if let Some(value) = since_vault_revision {
                if value != verified_revision {
                    return Err(CliError::Input(
                        "--since-vault-revision must match the locally verified checkpoint head",
                    ));
                }
                value
            } else {
                verified_revision
            };
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
                cache.quarantine_transport_failure(
                    vault_id,
                    since_vault_revision,
                    "missing",
                    code,
                )?;
                return Err(cache.integrity_error(vault_id)?);
            };
            let checkpoints = response
                .checkpoints
                .iter()
                .filter(|checkpoint| checkpoint.vault_id == vault_id)
                .cloned()
                .collect::<Vec<_>>();
            cache.verify_and_record_checkpoints(changes, &checkpoints)?;
            render_sync_response(output, &response)
        }
        Command::Sync(SyncCommand::Integrity(command)) => {
            let profile = active_profile(&config)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            match command {
                SyncIntegrityCommand::Status { vault_id, vault } => {
                    let vault_id = resolve_vault_id_for_output(
                        profile,
                        &cache,
                        vault_id,
                        vault.as_deref(),
                        output,
                    )?;
                    render_integrity_status(output, &cache.integrity_state(vault_id)?)
                }
                SyncIntegrityCommand::Export {
                    vault_id,
                    vault,
                    output: destination,
                } => {
                    let vault_id = resolve_vault_id_for_output(
                        profile,
                        &cache,
                        vault_id,
                        vault.as_deref(),
                        output,
                    )?;
                    let bundle = cache.export_checkpoint_evidence(vault_id)?;
                    write_forensics_bundle(&destination, &bundle)?;
                    if output.is_json() {
                        print_json(&serde_json::json!({
                            "vault_id": vault_id,
                            "output": destination,
                            "exported": true
                        }))
                    } else {
                        println!("integrity evidence written: {}", destination.display());
                        Ok(())
                    }
                }
                SyncIntegrityCommand::ExportTrustAnchors {
                    output: destination,
                } => {
                    let password = rpassword::prompt_password("Master password: ")?;
                    let unlocked = crate::crypto_state::load_unlocked_profile(
                        profile,
                        &MasterPassword::new(password.into_bytes()),
                    )?;
                    let bundle = authenticated_checkpoint_trust_bundle(
                        &unlocked,
                        &cache.trusted_checkpoint_devices()?,
                    )?;
                    let encoded = serde_json::to_string_pretty(&bundle)?;
                    std::fs::write(&destination, encoded)?;
                    if output.is_json() {
                        print_json(&serde_json::json!({
                            "output": destination,
                            "anchor_count": bundle.trusted_checkpoint_devices.len(),
                            "exported": true
                        }))
                    } else {
                        println!(
                            "checkpoint trust anchors written: {}",
                            destination.display()
                        );
                        Ok(())
                    }
                }
                SyncIntegrityCommand::ImportTrustAnchors { input } => {
                    let raw = std::fs::read_to_string(&input)?;
                    let bundle: umbra_crypto::checkpoint_trust::CheckpointTrustBundleV1 =
                        serde_json::from_str(&raw)?;
                    let password = rpassword::prompt_password("Master password: ")?;
                    let unlocked = crate::crypto_state::load_unlocked_profile(
                        profile,
                        &MasterPassword::new(password.into_bytes()),
                    )?;
                    let imported = import_checkpoint_trust_bundle(&cache, &unlocked, &bundle)?;
                    if output.is_json() {
                        print_json(&serde_json::json!({
                            "input": input,
                            "anchor_count": imported,
                            "imported": true
                        }))
                    } else {
                        println!("checkpoint trust anchors imported: {imported}");
                        Ok(())
                    }
                }
            }
        }
    }
}

fn require_login(profile: &crate::config::ProfileConfig) -> Result<(), CliError> {
    if profile.legacy_session_token.is_some()
        || (profile.session_id.is_some()
            && profile.device_id.is_some()
            && profile.device_private_key.is_some())
    {
        Ok(())
    } else {
        Err(CliError::NotLoggedIn)
    }
}

async fn load_env_bundle_for_command(
    config: &CliConfig,
    profile: &crate::config::ProfileConfig,
    output: OutputMode,
    project_env: &str,
    vault_id: Option<VaultId>,
    vault: Option<&str>,
    offline: bool,
) -> Result<ItemPlaintextV1, CliError> {
    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id = resolve_vault_id_for_output(profile, &cache, vault_id, vault, output)?;
    let mode = if offline {
        crate::sync::SyncMode::Offline
    } else {
        require_login(profile)?;
        crate::sync::SyncMode::IfChanged
    };
    let sync_outcome =
        crate::sync::ensure_vault_synced(profile, &mut cache, vault_id, mode).await?;
    let _ = (
        sync_outcome.synced,
        sync_outcome.latest_vault_revision,
        sync_outcome.latest_access_revision,
    );
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let Some((_revision, plaintext)) =
        find_secret_bundle(&cache, &vault_key, vault_id, project_env)?
    else {
        return Err(CliError::Input("secret bundle not found"));
    };
    Ok(plaintext)
}

#[allow(dead_code)]
fn ensure_can_write_env_file(path: &Path, yes: bool) -> Result<(), CliError> {
    if path.exists() && !yes {
        return Err(CliError::Input(
            "output file already exists; pass --yes to overwrite",
        ));
    }
    Ok(())
}

fn write_new_env_file(path: &Path, contents: &str) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);

    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            // This file can contain plaintext secrets. Do not leave a partial
            // temporary file behind when writing or syncing fails.
            let _ = std::fs::remove_file(path);
            Err(error.into())
        }
    }
}

fn write_env_file(path: &Path, contents: &str, overwrite: bool) -> Result<(), CliError> {
    if !overwrite {
        return match write_new_env_file(path, contents) {
            Ok(()) => Ok(()),
            Err(CliError::Io(error)) if error.kind() == ErrorKind::AlreadyExists => Err(
                CliError::Input("output file already exists; pass --yes to overwrite"),
            ),
            Err(error) => Err(error),
        };
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or(CliError::Input("output path must include a file name"))?;
    let temp_path = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        Uuid::new_v4()
    ));

    write_new_env_file(&temp_path, contents)?;

    match promote_env_temp_file(&temp_path, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temp_path);
            Err(error)
        }
    }
}

#[cfg(not(windows))]
fn promote_env_temp_file(temp_path: &Path, path: &Path) -> Result<(), CliError> {
    std::fs::rename(temp_path, path).map_err(CliError::from)
}

#[cfg(windows)]
fn promote_env_temp_file(temp_path: &Path, path: &Path) -> Result<(), CliError> {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    unsafe extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    let temp_path = wide_path(temp_path);
    let path = wide_path(path);
    // SAFETY: Both paths are null-terminated UTF-16 buffers that live for this
    // call. MOVEFILE_REPLACE_EXISTING asks Windows to replace the destination
    // atomically, without deleting it before the replacement succeeds.
    let result = unsafe {
        MoveFileExW(
            temp_path.as_ptr(),
            path.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn env_variables_json(plaintext: &ItemPlaintextV1) -> BTreeMap<String, String> {
    crate::item_plaintext::env_pairs(plaintext)
        .into_iter()
        .collect()
}

fn build_env_command(
    command: &[String],
    env_pairs: Vec<(String, String)>,
) -> Result<std::process::Command, CliError> {
    if command.is_empty() {
        return Err(CliError::Input("run requires a command after --"));
    }
    let mut child = std::process::Command::new(&command[0]);
    child.args(&command[1..]);
    child.envs(env_pairs);
    Ok(child)
}

fn save_pending_login_crypto_material(
    profile: &mut crate::config::ProfileConfig,
    encrypted_private_key: serde_json::Value,
) {
    profile.encrypted_user_private_key = Some(encrypted_private_key);
    profile.client_public_key = None;
    profile.kdf_params = None;
    profile.user_secret_key = None;
}

fn resolve_vault_id(
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: Option<VaultId>,
    vault_name: Option<&str>,
) -> Result<VaultId, CliError> {
    if vault_id.is_some() && vault_name.is_some() {
        return Err(CliError::Input(
            "use either --vault-id or --vault, not both",
        ));
    }

    if let Some(vault_id) = vault_id {
        return Ok(vault_id);
    }

    if let Some(vault_name) = vault_name {
        if let Ok(vault_id) = Uuid::parse_str(vault_name) {
            return Ok(vault_id);
        }

        let matches = cache.find_vaults_by_name(vault_name)?;
        return match matches.as_slice() {
            [vault] => Ok(vault.vault_id),
            [] => Err(CliError::Input(
                "vault not found in local cache; run `umbra vault list` first",
            )),
            _ => Err(CliError::Input(
                "vault name is ambiguous; pass --vault-id instead",
            )),
        };
    }

    profile.default_vault_id.ok_or(CliError::Input(
        "no default vault configured; pass --vault-id/--vault or create a vault first",
    ))
}

fn resolve_vault_id_for_output(
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: Option<VaultId>,
    vault_name: Option<&str>,
    output: OutputMode,
) -> Result<VaultId, CliError> {
    match resolve_vault_id(profile, cache, vault_id, vault_name) {
        Ok(vault_id) => Ok(vault_id),
        Err(CliError::Input(
            "no default vault configured; pass --vault-id/--vault or create a vault first",
        )) if !output.is_json() => {
            let vaults = cache.list_vaults()?;
            if vaults.is_empty() {
                return Err(CliError::Input(
                    "no cached vaults; run `umbra vault list` first",
                ));
            }

            crate::interactive::select_vault(&vaults)?
                .ok_or(CliError::Input("vault selection cancelled"))
        }
        Err(error) => Err(error),
    }
}

fn vault_create_path(org_id: Option<uuid::Uuid>) -> String {
    match org_id {
        Some(org_id) => format!("/api/v1/orgs/{org_id}/vaults"),
        None => "/api/v1/vaults".to_owned(),
    }
}

fn selected_unlock_vaults(
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: Option<VaultId>,
    vault_name: Option<&str>,
    all: bool,
) -> Result<Vec<VaultId>, CliError> {
    if all && (vault_id.is_some() || vault_name.is_some()) {
        return Err(CliError::Input(
            "use either --all or a single vault selector",
        ));
    }

    if all {
        let vaults = cache.cached_vault_ids()?;
        if vaults.is_empty() {
            return Err(CliError::Input(
                "no cached vaults; run `umbra vault list` first",
            ));
        }
        return Ok(vaults);
    }

    Ok(vec![resolve_vault_id(
        profile, cache, vault_id, vault_name,
    )?])
}

#[cfg(test)]
fn emergency_kit_json_from_profile(
    profile: &crate::config::ProfileConfig,
) -> Result<String, CliError> {
    emergency_kit_json_from_profile_with_trust_bundle(profile, None)
}

fn emergency_kit_json_from_profile_with_trust_bundle(
    profile: &crate::config::ProfileConfig,
    checkpoint_trust_bundle: Option<umbra_crypto::checkpoint_trust::CheckpointTrustBundleV1>,
) -> Result<String, CliError> {
    let mut kit = crate::crypto_state::EmergencyKitV1::from_profile(profile)?;
    kit.checkpoint_trust_bundle = checkpoint_trust_bundle;
    serde_json::to_string_pretty(&kit).map_err(CliError::from)
}

fn read_emergency_kit(
    path: &std::path::Path,
) -> Result<crate::crypto_state::EmergencyKitV1, CliError> {
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(CliError::from)
}

async fn lookup_user_by_email(
    client: &UmbraHttpClient,
    email: &str,
) -> Result<UserLookupResponse, CliError> {
    client
        .post(
            "/api/v1/users/lookup",
            &UserLookupRequest {
                protocol_version: PROTOCOL_VERSION,
                email: email.to_owned(),
            },
        )
        .await
}

async fn refresh_cached_vault_metadata(
    client: &UmbraHttpClient,
    cache: &crate::cache::LocalCache,
    vault_id: VaultId,
) -> Result<(), CliError> {
    let vaults: Vec<VaultResponse> = client.get("/api/v1/vaults").await?;
    let vault = vaults
        .iter()
        .find(|vault| vault.vault_id == vault_id)
        .ok_or(CliError::Input("vault list did not return selected vault"))?;
    cache.upsert_vault(vault)
}

fn apply_recovered_emergency_kit_material(
    profile: &mut crate::config::ProfileConfig,
    kit: &crate::crypto_state::EmergencyKitV1,
) -> Result<(), CliError> {
    if kit.version != 1 {
        return Err(CliError::Input("unsupported emergency kit version"));
    }

    profile.client_public_key = Some(kit.account_public_key.clone());
    profile.user_secret_key = Some(kit.user_secret_key.clone());
    profile.kdf_params = Some(kit.kdf_params.clone());
    profile.pending_approval_code = None;
    profile.legacy_session_token = None;
    profile.session_id = None;
    Ok(())
}

fn authenticated_checkpoint_trust_bundle(
    unlocked: &crate::crypto_state::UnlockedAccountCrypto,
    anchors: &[crate::cache::TrustedCheckpointDevice],
) -> Result<umbra_crypto::checkpoint_trust::CheckpointTrustBundleV1, CliError> {
    let anchors = anchors
        .iter()
        .map(|anchor| DeviceCheckpointTrustAnchorV1 {
            device_id: anchor.device_id.to_string(),
            public_key: anchor.public_key.clone(),
            revoked: anchor.revoked,
        })
        .collect();
    umbra_crypto::checkpoint_trust::authenticate_checkpoint_trust_bundle(
        &unlocked.private_key,
        &unlocked.public_key,
        anchors,
    )
    .map_err(|_| CliError::Input("failed to authenticate checkpoint trust anchors"))
}

fn checkpoint_anchors_from_emergency_kit(
    unlocked: &crate::crypto_state::UnlockedAccountCrypto,
    kit: &crate::crypto_state::EmergencyKitV1,
) -> Result<Vec<crate::cache::TrustedCheckpointDevice>, CliError> {
    match kit.checkpoint_trust_bundle.as_ref() {
        Some(bundle) => verified_checkpoint_trust_anchors(unlocked, bundle),
        None => Ok(Vec::new()),
    }
}

fn verified_checkpoint_trust_anchors(
    unlocked: &crate::crypto_state::UnlockedAccountCrypto,
    bundle: &umbra_crypto::checkpoint_trust::CheckpointTrustBundleV1,
) -> Result<Vec<crate::cache::TrustedCheckpointDevice>, CliError> {
    umbra_crypto::checkpoint_trust::verify_checkpoint_trust_bundle(
        &unlocked.private_key,
        &unlocked.public_key,
        bundle,
    )
    .map_err(|_| CliError::Input("checkpoint trust anchor authentication failed"))?
    .iter()
    .map(checkpoint_anchor_from_bootstrap)
    .collect()
}

fn record_checkpoint_trust_anchors(
    cache: &crate::cache::LocalCache,
    anchors: &[crate::cache::TrustedCheckpointDevice],
) -> Result<(), CliError> {
    let existing = cache
        .trusted_checkpoint_devices()?
        .into_iter()
        .map(|anchor| (anchor.device_id, anchor))
        .collect::<BTreeMap<_, _>>();
    for anchor in anchors {
        if let Some(current) = existing.get(&anchor.device_id)
            && current != anchor
        {
            return Err(CliError::Input(
                "checkpoint trust anchor conflicts with existing local trust",
            ));
        }
    }
    for anchor in anchors {
        cache.record_trusted_checkpoint_device(anchor)?;
    }
    Ok(())
}

fn import_checkpoint_trust_bundle(
    cache: &crate::cache::LocalCache,
    unlocked: &crate::crypto_state::UnlockedAccountCrypto,
    bundle: &umbra_crypto::checkpoint_trust::CheckpointTrustBundleV1,
) -> Result<usize, CliError> {
    let anchors = verified_checkpoint_trust_anchors(unlocked, bundle)?;
    record_checkpoint_trust_anchors(cache, &anchors)?;
    Ok(anchors.len())
}

fn device_bootstrap_bundle_from_profile(
    profile: &crate::config::ProfileConfig,
    trusted_checkpoint_devices: &[crate::cache::TrustedCheckpointDevice],
) -> Result<DeviceBootstrapBundleV1, CliError> {
    let user_secret_key = profile
        .user_secret_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)?;
    let kdf_params = profile
        .kdf_params
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)?;
    let encrypted_user_private_key = profile
        .encrypted_user_private_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| serde_json::from_value(value).map_err(CliError::from))?;
    let account_public_key = profile
        .client_public_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)?;

    Ok(DeviceBootstrapBundleV1 {
        version: 1,
        user_secret_key,
        kdf_params,
        encrypted_user_private_key,
        account_public_key,
        default_vault_id: profile.default_vault_id.map(|id| id.to_string()),
        trusted_checkpoint_devices: trusted_checkpoint_devices
            .iter()
            .map(|device| DeviceCheckpointTrustAnchorV1 {
                device_id: device.device_id.to_string(),
                public_key: device.public_key.clone(),
                revoked: device.revoked,
            })
            .collect(),
    })
}

fn checkpoint_anchor_from_device(
    device: &DeviceResponse,
) -> Result<crate::cache::TrustedCheckpointDevice, CliError> {
    let public_key = device
        .public_key
        .clone()
        .ok_or(CliError::Input("device has no signing public key"))?;
    if crate::keys::public_key_fingerprint(&public_key)? != device.fingerprint {
        return Err(CliError::Input(
            "device signing public key does not match its fingerprint",
        ));
    }
    Ok(crate::cache::TrustedCheckpointDevice {
        device_id: device.device_id,
        public_key,
        revoked: device.revoked_at.is_some(),
    })
}

fn checkpoint_anchor_from_bootstrap(
    anchor: &DeviceCheckpointTrustAnchorV1,
) -> Result<crate::cache::TrustedCheckpointDevice, CliError> {
    let device_id = Uuid::parse_str(&anchor.device_id)
        .map_err(|_| CliError::Input("invalid checkpoint device id in bootstrap bundle"))?;
    umbra_auth::verifying_key_from_b64(&anchor.public_key)
        .map_err(|_| CliError::Input("invalid checkpoint public key in bootstrap bundle"))?;
    Ok(crate::cache::TrustedCheckpointDevice {
        device_id,
        public_key: anchor.public_key.clone(),
        revoked: anchor.revoked,
    })
}

fn render_devices(output: OutputMode, devices: &[DeviceResponse]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(devices);
    }

    let rows = devices
        .iter()
        .map(|device| {
            vec![
                device.name.clone(),
                device.device_id.to_string(),
                format!("{:?}", device.state).to_ascii_lowercase(),
                device.fingerprint.clone(),
                device.trusted_at.clone().unwrap_or_else(|| "-".to_owned()),
                device.revoked_at.clone().unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(
        &[
            "name",
            "device_id",
            "state",
            "fingerprint",
            "trusted",
            "revoked",
        ],
        &rows,
    );
    Ok(())
}

fn render_pending_devices(
    output: OutputMode,
    devices: &[PendingDeviceSummary],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(devices);
    }

    let rows = devices
        .iter()
        .map(|device| {
            vec![
                device.name.clone(),
                device.device_id.to_string(),
                device.fingerprint.clone(),
                device.approval_expires_at.clone(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["name", "device_id", "fingerprint", "expires"], &rows);
    Ok(())
}

fn render_vaults(output: OutputMode, vaults: &[VaultResponse]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(&vaults);
    }

    let rows = vaults
        .iter()
        .map(|vault| {
            vec![
                vault.name.clone(),
                vault_kind_label(vault.kind).to_owned(),
                vault.vault_id.to_string(),
                vault.vault_revision.to_string(),
                vault.access_revision.to_string(),
                if vault.needs_key_rotation {
                    "yes".to_owned()
                } else {
                    "no".to_owned()
                },
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(
        &["name", "kind", "id", "vault_rev", "access_rev", "rotate"],
        &rows,
    );
    Ok(())
}

fn render_vault_created(output: OutputMode, vault: &VaultResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(vault);
    }

    crate::output::print_kv(&[
        ("created vault", vault.name.clone()),
        ("id", vault.vault_id.to_string()),
        ("kind", vault_kind_label(vault.kind).to_owned()),
    ]);
    Ok(())
}

fn render_item_revision_created(
    output: OutputMode,
    action: &str,
    response: &ItemRevisionResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(response);
    }

    crate::output::print_kv(&[
        ("action", action.to_owned()),
        ("item_id", response.item_id.to_string()),
        ("vault_id", response.vault_id.to_string()),
        ("revision", response.revision.to_string()),
        ("vault revision", response.vault_revision.to_string()),
    ]);
    Ok(())
}

fn render_item_deleted(
    output: OutputMode,
    vault_id: VaultId,
    item_id: ItemId,
    revision: RevisionId,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(&serde_json::json!({
            "deleted": true,
            "vault_id": vault_id,
            "item_id": item_id,
            "expected_revision": revision
        }));
    }

    crate::output::print_kv(&[
        ("deleted item", item_id.to_string()),
        ("vault_id", vault_id.to_string()),
        ("expected revision", revision.to_string()),
    ]);
    Ok(())
}

fn vault_kind_label(kind: VaultKind) -> &'static str {
    match kind {
        VaultKind::Personal => "personal",
        VaultKind::Shared => "shared",
        VaultKind::Project => "project",
        VaultKind::Org => "org",
    }
}

fn org_role_label(role: OrgRole) -> &'static str {
    match role {
        OrgRole::Owner => "owner",
        OrgRole::Admin => "admin",
        OrgRole::Member => "member",
    }
}

fn vault_role_label(role: VaultRole) -> &'static str {
    match role {
        VaultRole::Owner => "owner",
        VaultRole::Admin => "admin",
        VaultRole::Editor => "editor",
        VaultRole::Viewer => "viewer",
    }
}

fn member_state_label(state: MemberState) -> &'static str {
    match state {
        MemberState::Active => "active",
        MemberState::Invited => "invited",
        MemberState::Removed => "removed",
    }
}

fn resolve_target_user_id(
    explicit_user_id: Option<UserId>,
    lookup_user_id: Option<UserId>,
    email: Option<&str>,
) -> Result<UserId, CliError> {
    match (explicit_user_id, lookup_user_id, email) {
        (Some(user_id), None, None) => Ok(user_id),
        (None, Some(user_id), Some(_)) => Ok(user_id),
        (None, None, Some(_)) => Err(CliError::Input("user lookup did not return a user id")),
        (None, None, None) => Err(CliError::Input("pass --email or --user-id")),
        _ => Err(CliError::Input("pass only one of --email or --user-id")),
    }
}

fn render_orgs(output: OutputMode, orgs: &[OrgResponse]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(orgs);
    }
    let rows = orgs
        .iter()
        .map(|org| vec![org.name.clone(), org.org_id.to_string()])
        .collect::<Vec<_>>();
    crate::output::print_table(&["name", "org_id"], &rows);
    Ok(())
}

fn render_org_created(output: OutputMode, org: &OrgResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(org);
    }
    crate::output::print_kv(&[
        ("created org", org.name.clone()),
        ("id", org.org_id.to_string()),
    ]);
    Ok(())
}

fn render_org_members(output: OutputMode, members: &[OrgMemberResponse]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(members);
    }
    let rows = members
        .iter()
        .map(|member| {
            vec![
                member.user_id.to_string(),
                org_role_label(member.role).to_owned(),
                member_state_label(member.state).to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["user_id", "role", "state"], &rows);
    Ok(())
}

fn render_org_member_added(output: OutputMode, member: &OrgMemberResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(member);
    }
    crate::output::print_kv(&[
        ("org_id", member.org_id.to_string()),
        ("user_id", member.user_id.to_string()),
        ("role", org_role_label(member.role).to_owned()),
        ("state", member_state_label(member.state).to_owned()),
    ]);
    Ok(())
}

fn render_vault_members(
    output: OutputMode,
    members: &[VaultMemberResponse],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(members);
    }
    let rows = members
        .iter()
        .map(|member| {
            vec![
                member.user_id.to_string(),
                vault_role_label(member.role).to_owned(),
                member_state_label(member.state).to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["user_id", "role", "state"], &rows);
    Ok(())
}

fn render_vault_member_added(
    output: OutputMode,
    member: &VaultMemberResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(member);
    }
    crate::output::print_kv(&[
        ("vault_id", member.vault_id.to_string()),
        ("user_id", member.user_id.to_string()),
        ("role", vault_role_label(member.role).to_owned()),
        ("state", member_state_label(member.state).to_owned()),
    ]);
    Ok(())
}

fn render_invite_created(output: OutputMode, invite: &InviteResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(invite);
    }
    crate::output::print_kv(&[
        ("invite_id", invite.invite_id.to_string()),
        ("vault_id", invite.vault_id.to_string()),
        ("email", invite.email.clone()),
        ("role", vault_role_label(invite.role).to_owned()),
        ("state", invite.state.clone()),
    ]);
    Ok(())
}

fn render_pending_invites(
    output: OutputMode,
    invites: &[PendingInviteResponse],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(invites);
    }
    let rows = invites
        .iter()
        .map(|invite| {
            vec![
                invite.invite_id.to_string(),
                invite.vault_name.clone(),
                invite.vault_id.to_string(),
                vault_role_label(invite.role).to_owned(),
                invite
                    .expires_at
                    .clone()
                    .unwrap_or_else(|| "never".to_owned()),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(
        &["invite_id", "vault", "vault_id", "role", "expires"],
        &rows,
    );
    Ok(())
}

fn render_invite_accepted(
    output: OutputMode,
    member: &VaultMemberResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(member);
    }
    crate::output::print_kv(&[
        ("accepted vault", member.vault_id.to_string()),
        ("role", vault_role_label(member.role).to_owned()),
        ("state", member_state_label(member.state).to_owned()),
    ]);
    Ok(())
}

fn render_invite_rejected(output: OutputMode, invite: &InviteResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(invite);
    }
    crate::output::print_kv(&[
        ("invite_id", invite.invite_id.to_string()),
        ("state", invite.state.clone()),
    ]);
    Ok(())
}

fn render_cache_status(
    output: OutputMode,
    status: &crate::cache::CacheStatus,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(status);
    }

    crate::output::print_kv(&[
        ("profile", status.profile.clone()),
        ("synced vaults", status.synced_vault_count.to_string()),
        ("item revisions", status.item_revision_count.to_string()),
        ("key wrappings", status.key_wrapping_count.to_string()),
        ("sync states", status.sync_state_count.to_string()),
    ]);
    Ok(())
}

fn render_unlock_status(
    output: OutputMode,
    status: &crate::unlock_store::UnlockStatus,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(status);
    }

    crate::output::print_kv(&[
        ("profile", status.profile.clone()),
        ("unlocked", status.unlocked.to_string()),
        (
            "expires",
            status
                .expires_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "-".to_owned()),
        ),
        ("vaults", status.vault_count.to_string()),
    ]);
    Ok(())
}

fn render_sync_response(output: OutputMode, response: &SyncResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(response);
    }

    let rows = response
        .vaults
        .iter()
        .map(|vault| {
            vec![
                vault.vault_id.to_string(),
                vault.latest_vault_revision.to_string(),
                vault.latest_access_revision.to_string(),
                vault.items.len().to_string(),
                vault.key_wrappings.len().to_string(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(
        &["vault_id", "vault_rev", "access_rev", "items", "wrappings"],
        &rows,
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct IntegrityStatusOutput {
    vault_id: VaultId,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_revision: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_id: Option<String>,
    finding_count: usize,
}

fn integrity_status_output(state: &crate::cache::VaultIntegrityState) -> IntegrityStatusOutput {
    let finding = state.findings.last();
    IntegrityStatusOutput {
        vault_id: state.vault_id,
        state: if state.unsafe_sync {
            "unsafe"
        } else if state.verified_head.is_some() {
            "verified"
        } else {
            "uninitialized"
        },
        error_code: finding.map(|finding| finding.code.clone()),
        verified_revision: state
            .verified_head
            .as_ref()
            .map(|head| head.checkpoint.vault_revision),
        checkpoint_id: finding
            .map(|finding| finding.checkpoint_hash.clone())
            .or_else(|| {
                state
                    .verified_head
                    .as_ref()
                    .map(|head| head.checkpoint_hash.clone())
            }),
        finding_count: state.findings.len(),
    }
}

fn render_integrity_status(
    output: OutputMode,
    state: &crate::cache::VaultIntegrityState,
) -> Result<(), CliError> {
    let status = integrity_status_output(state);
    if output.is_json() {
        return print_json(&status);
    }
    crate::output::print_kv(&[
        ("vault_id", status.vault_id.to_string()),
        ("state", status.state.to_owned()),
        (
            "error_code",
            status.error_code.unwrap_or_else(|| "-".to_owned()),
        ),
        (
            "verified_revision",
            status
                .verified_revision
                .map(|revision| revision.to_string())
                .unwrap_or_else(|| "-".to_owned()),
        ),
        (
            "checkpoint_id",
            status.checkpoint_id.unwrap_or_else(|| "-".to_owned()),
        ),
        ("findings", status.finding_count.to_string()),
    ]);
    Ok(())
}

fn write_forensics_bundle(
    path: &Path,
    bundle: &crate::cache::CheckpointForensicsBundle,
) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            CliError::Input("integrity export destination already exists")
        } else {
            CliError::Io(error)
        }
    })?;
    serde_json::to_writer_pretty(&mut file, bundle)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn render_rotation_status(
    output: OutputMode,
    status: &RotationStatusResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(status);
    }

    crate::output::print_kv(&[
        ("vault_id", status.vault_id.to_string()),
        (
            "current key generation",
            status.current_key_generation.to_string(),
        ),
        (
            "needs key rotation",
            if status.needs_key_rotation {
                "yes"
            } else {
                "no"
            }
            .to_owned(),
        ),
    ]);
    Ok(())
}

fn render_rotation_complete(
    output: OutputMode,
    status: &RotationStatusResponse,
    summary: &RotationPlanSummary,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(&serde_json::json!({
            "status": status,
            "summary": summary,
        }));
    }

    crate::output::print_kv(&[
        ("vault_id", status.vault_id.to_string()),
        ("from generation", summary.from_generation.to_string()),
        ("to generation", summary.to_generation.to_string()),
        (
            "member wrappings",
            summary.member_wrapping_count.to_string(),
        ),
        ("reencrypted items", summary.item_revision_count.to_string()),
        (
            "needs key rotation",
            if status.needs_key_rotation {
                "yes"
            } else {
                "no"
            }
            .to_owned(),
        ),
    ]);
    Ok(())
}

fn render_rotation_dry_run(
    output: OutputMode,
    summary: &RotationPlanSummary,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(summary);
    }

    crate::output::print_kv(&[
        ("vault_id", summary.vault_id.to_string()),
        ("from generation", summary.from_generation.to_string()),
        ("to generation", summary.to_generation.to_string()),
        (
            "member wrappings",
            summary.member_wrapping_count.to_string(),
        ),
        (
            "items to reencrypt",
            summary.item_revision_count.to_string(),
        ),
        ("dry run", "yes".to_owned()),
    ]);
    Ok(())
}

fn render_item_plaintext(
    output: OutputMode,
    item_id: Uuid,
    plaintext: &ItemPlaintextV1,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(plaintext);
    }

    crate::output::print_kv(&[
        ("item_id", item_id.to_string()),
        ("title", plaintext.title.clone()),
        (
            "tags",
            if plaintext.tags.is_empty() {
                "-".to_owned()
            } else {
                plaintext.tags.join(",")
            },
        ),
    ]);

    if !plaintext.fields.is_empty() {
        println!();
        let rows = plaintext
            .fields
            .iter()
            .map(|field| {
                vec![
                    field.name.clone(),
                    format!("{:?}", field.kind),
                    if field.sensitive {
                        "[secret]".to_owned()
                    } else {
                        field.value.clone()
                    },
                ]
            })
            .collect::<Vec<_>>();
        crate::output::print_table(&["field", "kind", "value"], &rows);
    }
    Ok(())
}

fn render_item_list(output: OutputMode, items: &[DecryptedListedItem]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(&items);
    }

    let rows = items
        .iter()
        .map(|item| {
            vec![
                item.title.clone(),
                item.kind.clone(),
                item.item_id.to_string(),
                item.revision.to_string(),
                item.field_count.to_string(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["title", "kind", "item_id", "rev", "fields"], &rows);
    Ok(())
}

fn decrypted_listed_items(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
) -> Result<Vec<DecryptedListedItem>, CliError> {
    let mut items = Vec::new();
    for revision in cache.list_latest_item_revisions(vault_id)? {
        let Ok(wrapper) = serde_json::from_value::<ItemEnvelopeWrapper>(revision.envelope.clone())
        else {
            continue;
        };
        let kind = wrapper.kind.clone();
        let item = decrypt_cached_item_wrapper(vault_key, &revision, wrapper)?;
        items.push(DecryptedListedItem {
            item_id: revision.item_id,
            title: item.plaintext.title,
            kind,
            revision: revision.revision,
            field_count: item.plaintext.fields.len(),
        });
    }
    Ok(items)
}

fn find_secret_bundle(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
    project_env: &str,
) -> Result<Option<(crate::cache::CachedItemRevision, ItemPlaintextV1)>, CliError> {
    for revision in cache.list_latest_item_revisions(vault_id)? {
        let Ok(wrapper) = serde_json::from_value::<ItemEnvelopeWrapper>(revision.envelope.clone())
        else {
            continue;
        };
        if wrapper.kind != "env_bundle" {
            continue;
        }
        let item = decrypt_cached_item_wrapper(vault_key, &revision, wrapper)?;
        if item.plaintext.title == project_env {
            return Ok(Some((revision, item.plaintext)));
        }
    }
    Ok(None)
}

fn render_secret_list(output: OutputMode, plaintext: &ItemPlaintextV1) -> Result<(), CliError> {
    let bundle = listed_secret_bundle(plaintext);
    if output.is_json() {
        return print_json(&bundle);
    }

    crate::output::print_table(&["key", "kind", "sensitive"], &listed_secret_rows(&bundle));
    Ok(())
}

fn resolve_secret_key_for_output(
    key: Option<String>,
    plaintext: &ItemPlaintextV1,
    output: OutputMode,
) -> Result<String, CliError> {
    if let Some(key) = key {
        return Ok(key);
    }

    if output.is_json() {
        return Err(CliError::Input("pass a secret key"));
    }

    crate::interactive::select_secret_key(plaintext)?
        .ok_or(CliError::Input("secret key selection cancelled"))
}

fn listed_secret_bundle(plaintext: &ItemPlaintextV1) -> ListedSecretBundle {
    ListedSecretBundle {
        project_env: plaintext.title.clone(),
        fields: plaintext
            .fields
            .iter()
            .map(|field| ListedSecretField {
                key: field.name.clone(),
                kind: format!("{:?}", field.kind),
                sensitive: field.sensitive,
            })
            .collect(),
    }
}

fn listed_secret_rows(bundle: &ListedSecretBundle) -> Vec<Vec<String>> {
    bundle
        .fields
        .iter()
        .map(|field| {
            vec![
                field.key.clone(),
                field.kind.clone(),
                if field.sensitive {
                    "yes".to_owned()
                } else {
                    "no".to_owned()
                },
            ]
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
struct ListedSecretField {
    key: String,
    kind: String,
    sensitive: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ListedSecretBundle {
    project_env: String,
    fields: Vec<ListedSecretField>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DecryptedListedItem {
    pub(crate) item_id: Uuid,
    pub(crate) title: String,
    pub(crate) kind: String,
    pub(crate) revision: i64,
    pub(crate) field_count: usize,
}

struct DecryptedCachedItem {
    kind: String,
    plaintext: ItemPlaintextV1,
}

enum ItemSelectionNeed {
    Selected(crate::cache::CachedItemRevision),
    NeedsTitleDecrypt,
    NeedsInteractiveDecrypt,
}

fn unlock_vault_key(
    profile_name: &str,
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: VaultId,
) -> Result<VaultKey, CliError> {
    let cached_vault_key = crate::unlock_store::UnlockStore::open(profile_name, profile.device_id)
        .load()?
        .and_then(|state| state.vault_key(vault_id));
    if let Some(vault_key) = cached_vault_key {
        return Ok(vault_key);
    }

    let user_id = profile.user_id.ok_or(CliError::Input(
        "profile has no user id; run `umbra login` first",
    ))?;
    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra register` first",
    ))?;
    let device_private_key =
        UserPrivateKey::from_base64url(profile.device_encryption_private_key.as_deref().ok_or(
            CliError::Input("profile has no device encryption key; re-enroll this device"),
        )?)?;
    let wrapping = cache
        .latest_device_key_wrapping(vault_id, user_id, device_id)?
        .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
    let envelope: VaultKeyWrappingEnvelopeV1 = serde_json::from_value(wrapping.envelope)?;
    let aad = AadV1::device_vault_key_wrapping(
        vault_id.to_string(),
        device_id.to_string(),
        wrapping.key_generation,
    );

    unwrap_vault_key(&device_private_key, &aad, &envelope).map_err(CliError::from)
}

fn save_rotated_vault_key_to_unlock_store(
    profile_name: &str,
    profile: &crate::config::ProfileConfig,
    vault_id: VaultId,
    new_vault_key: VaultKey,
) -> Result<(), CliError> {
    let Some(mut state) =
        crate::unlock_store::UnlockStore::open(profile_name, profile.device_id).load()?
    else {
        return Ok(());
    };
    state.vault_keys.insert(vault_id, new_vault_key);
    crate::unlock_store::UnlockStore::open(profile_name, profile.device_id).save(&state)
}

fn wrap_vault_key_for_member(
    recipient_public_key: &UserPublicKey,
    vault_key: &VaultKey,
    vault_id: VaultId,
) -> Result<Value, CliError> {
    let aad = AadV1::vault_key_wrapping(vault_id.to_string());
    let wrapping = wrap_vault_key_for_user(recipient_public_key, vault_key, aad)?;
    serde_json::to_value(wrapping).map_err(CliError::from)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RotationPlanSummary {
    vault_id: VaultId,
    from_generation: i64,
    to_generation: i64,
    member_wrapping_count: usize,
    item_revision_count: usize,
    dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RotationCacheSnapshot {
    item_ids: BTreeSet<ItemId>,
}

impl RotationCacheSnapshot {
    fn full_vault(item_ids: impl IntoIterator<Item = ItemId>) -> Self {
        Self {
            item_ids: item_ids.into_iter().collect(),
        }
    }
}

fn rotation_next_generation(current_key_generation: i64) -> Result<i64, CliError> {
    if current_key_generation < 1 {
        return Err(CliError::Input("current key generation must be positive"));
    }
    Ok(current_key_generation + 1)
}

fn build_rotation_request(
    vault_id: VaultId,
    from_generation: i64,
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    members: &[VaultMemberResponse],
    current_revisions: &[crate::cache::CachedItemRevision],
    cache_snapshot: RotationCacheSnapshot,
) -> Result<RotateVaultKeyRequest, CliError> {
    let to_generation = rotation_next_generation(from_generation)?;
    if members.iter().any(|member| member.vault_id != vault_id) {
        return Err(CliError::Input(
            "vault member response does not belong to selected vault",
        ));
    }
    let active_members = members
        .iter()
        .filter(|member| member.state == MemberState::Active)
        .collect::<Vec<_>>();
    if active_members.is_empty() {
        return Err(CliError::Input(
            "cannot rotate a vault with no active members",
        ));
    }

    let mut current_item_ids = BTreeSet::new();
    for revision in current_revisions {
        if !current_item_ids.insert(revision.item_id) {
            return Err(CliError::Input(
                "cached item snapshot is incomplete; run a full sync and try again",
            ));
        }
    }
    if current_item_ids != cache_snapshot.item_ids {
        return Err(CliError::Input(
            "cached item snapshot is incomplete; run a full sync and try again",
        ));
    }

    let mut new_wrappings = Vec::with_capacity(active_members.len());
    for member in active_members {
        let public_key = UserPublicKey::from_base64url(&member.public_key)?;
        new_wrappings.push(RotationVaultKeyWrapping {
            user_id: member.user_id,
            device_id: None,
            wrapping_type: "user_public_key".to_owned(),
            envelope: wrap_vault_key_for_member(&public_key, new_vault_key, vault_id)?,
        });
    }

    let mut reencrypted_revisions = Vec::with_capacity(current_revisions.len());
    for revision in current_revisions {
        if revision.key_generation != from_generation {
            return Err(CliError::Input(
                "cached item generation is stale; run `umbra sync run --force-full` and try again",
            ));
        }
        let decrypted = decrypt_cached_item(old_vault_key, revision)?;
        let next_revision = revision.revision + 1;
        let envelope = encrypt_item_plaintext(
            vault_id,
            revision.item_id,
            next_revision,
            decrypted.kind,
            new_vault_key,
            &decrypted.plaintext,
        )?;
        reencrypted_revisions.push(RotationItemRevision {
            item_id: revision.item_id,
            expected_revision: revision.revision,
            envelope,
        });
    }

    Ok(RotateVaultKeyRequest {
        protocol_version: PROTOCOL_VERSION,
        from_generation,
        to_generation,
        new_wrappings,
        reencrypted_revisions,
    })
}

fn encrypt_item_plaintext(
    vault_id: VaultId,
    item_id: Uuid,
    revision: i64,
    kind_name: String,
    vault_key: &VaultKey,
    plaintext: &ItemPlaintextV1,
) -> Result<Value, CliError> {
    let aad = AadV1::item(
        vault_id.to_string(),
        item_id.to_string(),
        revision,
        kind_name.clone(),
    );
    let crypto = encrypt_item(vault_key, aad, &serde_json::to_vec(plaintext)?)?;
    Ok(serde_json::to_value(ItemEnvelopeWrapper {
        kind: kind_name,
        crypto,
    })?)
}

fn decrypt_cached_item(
    vault_key: &VaultKey,
    revision: &crate::cache::CachedItemRevision,
) -> Result<DecryptedCachedItem, CliError> {
    let wrapper: ItemEnvelopeWrapper = serde_json::from_value(revision.envelope.clone())?;
    decrypt_cached_item_wrapper(vault_key, revision, wrapper)
}

fn select_cached_item_revision_before_unlock_for_output(
    cache: &crate::cache::LocalCache,
    vault_id: VaultId,
    item_id: Option<Uuid>,
    title: Option<&str>,
    output: OutputMode,
) -> Result<ItemSelectionNeed, CliError> {
    if item_id.is_some() && title.is_some() {
        return Err(CliError::Input("use either --item-id or --title, not both"));
    }

    if let Some(item_id) = item_id {
        return cache
            .latest_item_revision(vault_id, item_id)?
            .ok_or(CliError::Input("cached item not found"))
            .map(ItemSelectionNeed::Selected);
    }

    if title.is_some() {
        return Ok(ItemSelectionNeed::NeedsTitleDecrypt);
    }

    if output.is_json() {
        return Err(CliError::Input("pass --item-id or --title"));
    }

    Ok(ItemSelectionNeed::NeedsInteractiveDecrypt)
}

fn select_cached_item_revision_by_title(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
    title: &str,
) -> Result<crate::cache::CachedItemRevision, CliError> {
    let mut matches = Vec::new();
    for revision in cache.list_latest_item_revisions(vault_id)? {
        let item = decrypt_cached_item(vault_key, &revision)?;
        if item.plaintext.title == title {
            matches.push(revision);
        }
    }

    match matches.as_slice() {
        [revision] => Ok(revision.clone()),
        [] => Err(CliError::Input("cached item title not found")),
        _ => Err(CliError::Input("item title is ambiguous; pass --item-id")),
    }
}

fn select_cached_item_revision_interactively(
    cache: &crate::cache::LocalCache,
    vault_key: &VaultKey,
    vault_id: VaultId,
) -> Result<crate::cache::CachedItemRevision, CliError> {
    let items = decrypted_listed_items(cache, vault_key, vault_id)?;
    let item_id = crate::interactive::select_item(&items)?
        .ok_or(CliError::Input("item selection cancelled"))?;
    cache
        .latest_item_revision(vault_id, item_id)?
        .ok_or(CliError::Input("cached item not found"))
}

fn decrypt_cached_item_wrapper(
    vault_key: &VaultKey,
    revision: &crate::cache::CachedItemRevision,
    wrapper: ItemEnvelopeWrapper,
) -> Result<DecryptedCachedItem, CliError> {
    let aad = AadV1::item(
        revision.vault_id.to_string(),
        revision.item_id.to_string(),
        revision.revision,
        wrapper.kind.clone(),
    );
    let plaintext = decrypt_item(vault_key, &aad, &wrapper.crypto)?;

    Ok(DecryptedCachedItem {
        kind: wrapper.kind,
        plaintext: serde_json::from_slice(&plaintext)?,
    })
}

pub(crate) fn parse_field_pairs(values: Vec<String>) -> Result<Vec<(String, String)>, CliError> {
    values
        .into_iter()
        .map(|value| {
            let (name, field_value) = value
                .split_once('=')
                .ok_or(CliError::Input("field must use name=value"))?;
            if name.is_empty() {
                return Err(CliError::Input("field name cannot be empty"));
            }
            Ok((name.to_owned(), field_value.to_owned()))
        })
        .collect()
}

pub(crate) fn item_kind_name(kind: &ItemKind) -> String {
    match kind {
        ItemKind::Login => "login".to_owned(),
        ItemKind::SecureNote => "secure_note".to_owned(),
        ItemKind::SshKey => "ssh_key".to_owned(),
        ItemKind::ApiKey => "api_key".to_owned(),
        ItemKind::Token => "token".to_owned(),
        ItemKind::EnvVar => "env_var".to_owned(),
        ItemKind::EnvBundle => "env_bundle".to_owned(),
        ItemKind::CreditCard => "credit_card".to_owned(),
        ItemKind::Custom(name) => format!("custom:{name}"),
    }
}

pub fn parse_item_kind(value: &str) -> Result<ItemKind, String> {
    match value {
        "login" => Ok(ItemKind::Login),
        "secure_note" => Ok(ItemKind::SecureNote),
        "ssh_key" => Ok(ItemKind::SshKey),
        "api_key" => Ok(ItemKind::ApiKey),
        "token" => Ok(ItemKind::Token),
        "env_var" => Ok(ItemKind::EnvVar),
        "env_bundle" => Ok(ItemKind::EnvBundle),
        "credit_card" => Ok(ItemKind::CreditCard),
        custom if custom.starts_with("custom:") => Ok(ItemKind::Custom(
            custom.trim_start_matches("custom:").to_owned(),
        )),
        _ => Err("expected known kind or custom:<name>".to_owned()),
    }
}

pub fn parse_org_role(value: &str) -> Result<umbra_core::OrgRole, String> {
    match value {
        "owner" => Ok(umbra_core::OrgRole::Owner),
        "admin" => Ok(umbra_core::OrgRole::Admin),
        "member" => Ok(umbra_core::OrgRole::Member),
        _ => Err("expected one of: owner, admin, member".to_owned()),
    }
}

pub fn parse_vault_role(value: &str) -> Result<umbra_core::VaultRole, String> {
    match value {
        "owner" => Ok(umbra_core::VaultRole::Owner),
        "admin" => Ok(umbra_core::VaultRole::Admin),
        "editor" => Ok(umbra_core::VaultRole::Editor),
        "viewer" => Ok(umbra_core::VaultRole::Viewer),
        _ => Err("expected one of: owner, admin, editor, viewer".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_list_output_omits_candidate_envelopes_and_plaintext() {
        let conflict_id = Uuid::parse_str("00000000-0000-0000-0000-000000000801").unwrap();
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000802").unwrap();
        let conflict = crate::cache::CachedItemConflict {
            conflict_id,
            vault_id: Uuid::parse_str("00000000-0000-0000-0000-000000000803").unwrap(),
            item_id,
            base_revision: 4,
            current_revision: 5,
            candidate_kind: "update".to_owned(),
            candidate_envelope: Some(serde_json::json!({"ciphertext": "AAECAwQFBgcICQ"})),
            author_user_id: Some(Uuid::parse_str("00000000-0000-0000-0000-000000000804").unwrap()),
            state: "open".to_owned(),
        };

        assert_eq!(
            conflict_list_table_rows(std::slice::from_ref(&conflict)),
            vec![vec![
                conflict_id.to_string(),
                item_id.to_string(),
                "4".to_owned(),
                "5".to_owned(),
                "update".to_owned(),
                "00000000-0000-0000-0000-000000000804".to_owned(),
                "open".to_owned(),
            ]]
        );
        assert_eq!(
            serde_json::to_value(conflict_list_json(std::slice::from_ref(&conflict))).unwrap(),
            serde_json::json!([{
                "conflict_id": conflict_id,
                "item_id": item_id,
                "base_revision": 4,
                "current_revision": 5,
                "candidate_kind": "update",
                "author_user_id": "00000000-0000-0000-0000-000000000804",
                "state": "open",
            }])
        );
    }

    #[test]
    fn manual_merge_posts_only_a_ciphertext_wrapper() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000811").unwrap();
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000812").unwrap();
        let conflict_id = Uuid::parse_str("00000000-0000-0000-0000-000000000813").unwrap();
        let vault_key = generate_vault_key();
        let remote_plaintext = crate::item_plaintext::build_secret_bundle(
            "personal/prod",
            "REMOTE_ONLY",
            "remote-secret",
        );
        let mut local_plaintext =
            crate::item_plaintext::build_secret_bundle("personal/prod", "NAME", "secret-value");
        crate::item_plaintext::set_plaintext_field(
            &mut local_plaintext,
            "REMOVE_ME",
            "local-only".to_owned(),
        );
        crate::item_plaintext::set_plaintext_field(
            &mut local_plaintext,
            "API_TOKEN",
            "unchanged-sensitive-value".to_owned(),
        );
        let remote_revision = crate::cache::CachedItemRevision {
            vault_id,
            item_id,
            revision: 2,
            vault_revision: 2,
            key_generation: 1,
            author_user_id: None,
            envelope: encrypt_item_plaintext(
                vault_id,
                item_id,
                2,
                "secret_bundle".to_owned(),
                &vault_key,
                &remote_plaintext,
            )
            .unwrap(),
        };
        let local_candidate = crate::cache::CachedItemRevision {
            vault_id,
            item_id,
            revision: 2,
            vault_revision: 2,
            key_generation: 1,
            author_user_id: None,
            envelope: encrypt_item_plaintext(
                vault_id,
                item_id,
                2,
                "secret_bundle".to_owned(),
                &vault_key,
                &local_plaintext,
            )
            .unwrap(),
        };

        let remote = decrypt_cached_item(&vault_key, &remote_revision).unwrap();
        let mut local = decrypt_cached_item(&vault_key, &local_candidate).unwrap();
        assert_eq!(remote.plaintext.title, "personal/prod");
        assert!(
            local
                .plaintext
                .fields
                .iter()
                .any(|field| field.name == "API_TOKEN" && field.sensitive)
        );
        crate::item_plaintext::set_plaintext_field(
            &mut local.plaintext,
            "NAME",
            "merged-value".to_owned(),
        );
        assert!(crate::item_plaintext::remove_plaintext_field(
            &mut local.plaintext,
            "REMOVE_ME"
        ));
        local.plaintext.title = "T".to_owned();
        local.plaintext.notes = Some("N".to_owned());

        let aad = AadV1::item(
            vault_id.to_string(),
            item_id.to_string(),
            remote_revision.revision + 1,
            local.kind.clone(),
        );
        let final_wrapper = ItemEnvelopeWrapper {
            kind: local.kind,
            crypto: encrypt_item(
                &vault_key,
                aad,
                &serde_json::to_vec(&local.plaintext).unwrap(),
            )
            .unwrap(),
        };
        let post = ResolveItemConflictRequest {
            protocol_version: PROTOCOL_VERSION,
            conflict_id,
            expected_current_revision: remote_revision.revision,
            resolution: "merge".to_owned(),
            envelope: Some(serde_json::to_value(final_wrapper).unwrap()),
        };
        let serialized_post = serde_json::to_value(post).unwrap();

        assert!(serialized_post["envelope"]["crypto"]["ciphertext"].is_string());
        assert!(!serialized_post.to_string().contains("secret-value"));
        assert!(
            !serialized_post
                .to_string()
                .contains("unchanged-sensitive-value")
        );
    }

    #[test]
    fn profile_public_key_reads_configured_key() {
        let public_key = UserPublicKey::from_bytes([7; 32]);
        let profile = crate::config::ProfileConfig {
            client_public_key: Some(public_key.to_base64url()),
            ..crate::config::ProfileConfig::default()
        };

        assert_eq!(profile_public_key(&profile).unwrap(), public_key);
    }

    #[test]
    fn profile_public_key_requires_configured_key() {
        let profile = crate::config::ProfileConfig::default();

        assert!(matches!(
            profile_public_key(&profile),
            Err(CliError::Input(
                "profile has no account public key; run `umbra register` for this profile"
            ))
        ));
    }

    #[test]
    fn role_labels_are_stable_for_membership_output() {
        assert_eq!(org_role_label(umbra_core::OrgRole::Owner), "owner");
        assert_eq!(org_role_label(umbra_core::OrgRole::Admin), "admin");
        assert_eq!(org_role_label(umbra_core::OrgRole::Member), "member");
        assert_eq!(vault_role_label(umbra_core::VaultRole::Owner), "owner");
        assert_eq!(vault_role_label(umbra_core::VaultRole::Admin), "admin");
        assert_eq!(vault_role_label(umbra_core::VaultRole::Editor), "editor");
        assert_eq!(vault_role_label(umbra_core::VaultRole::Viewer), "viewer");
    }

    #[test]
    fn resolve_target_user_requires_exactly_one_selector() {
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(
            resolve_target_user_id(Some(user_id), None, None).unwrap(),
            user_id
        );
        assert!(matches!(
            resolve_target_user_id(Some(user_id), Some(user_id), None),
            Err(CliError::Input(_))
        ));
        assert!(matches!(
            resolve_target_user_id(None, None, None),
            Err(CliError::Input(_))
        ));
    }

    #[test]
    fn vault_create_path_uses_org_endpoint_when_org_id_is_present() {
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(vault_create_path(None), "/api/v1/vaults");
        assert_eq!(
            vault_create_path(Some(org_id)),
            "/api/v1/orgs/00000000-0000-0000-0000-000000000001/vaults"
        );
    }

    #[test]
    fn member_vault_key_wrapping_roundtrips_for_target_user() {
        let target = generate_user_keypair();
        let vault_key = generate_vault_key();
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        let wrapping = wrap_vault_key_for_member(&target.public_key, &vault_key, vault_id).unwrap();
        let envelope: VaultKeyWrappingEnvelopeV1 = serde_json::from_value(wrapping).unwrap();
        let aad = AadV1::vault_key_wrapping(vault_id.to_string());
        let opened = unwrap_vault_key(&target.private_key, &aad, &envelope).unwrap();

        assert_eq!(opened, vault_key);
    }

    #[test]
    fn rotation_next_generation_rejects_invalid_current_generation() {
        assert!(rotation_next_generation(0).is_err());
        assert!(rotation_next_generation(-1).is_err());
        assert_eq!(rotation_next_generation(1).unwrap(), 2);
    }

    #[test]
    fn build_rotation_request_rewraps_members_and_reencrypts_items() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let member_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let old_vault_key = generate_vault_key();
        let new_vault_key = generate_vault_key();
        let member_keys = generate_user_keypair();
        let plaintext = ItemPlaintextV1 {
            schema_version: 1,
            title: "GitHub".to_owned(),
            fields: vec![],
            notes: Some("rotated".to_owned()),
            tags: vec![],
        };
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let envelope = encrypt_item_plaintext(
            vault_id,
            item_id,
            1,
            "login".to_owned(),
            &old_vault_key,
            &plaintext,
        )
        .unwrap();
        let revision = crate::cache::CachedItemRevision {
            vault_id,
            item_id,
            revision: 1,
            vault_revision: 1,
            key_generation: 1,
            author_user_id: None,
            envelope,
        };
        let member = VaultMemberResponse {
            vault_id,
            user_id: member_id,
            role: VaultRole::Editor,
            state: MemberState::Active,
            public_key: member_keys.public_key.to_base64url(),
        };

        let request = build_rotation_request(
            vault_id,
            1,
            &old_vault_key,
            &new_vault_key,
            &[member],
            &[revision],
            RotationCacheSnapshot::full_vault([item_id]),
        )
        .unwrap();

        assert_eq!(request.from_generation, 1);
        assert_eq!(request.to_generation, 2);
        assert_eq!(request.new_wrappings.len(), 1);
        assert_eq!(request.new_wrappings[0].user_id, member_id);
        assert_eq!(request.new_wrappings[0].wrapping_type, "user_public_key");
        assert_eq!(request.reencrypted_revisions.len(), 1);
        assert_eq!(request.reencrypted_revisions[0].expected_revision, 1);

        let wrapping: VaultKeyWrappingEnvelopeV1 =
            serde_json::from_value(request.new_wrappings[0].envelope.clone()).unwrap();
        let wrapping_aad = AadV1::vault_key_wrapping(vault_id.to_string());
        let opened = unwrap_vault_key(&member_keys.private_key, &wrapping_aad, &wrapping).unwrap();
        assert_eq!(opened, new_vault_key);

        let wrapper: ItemEnvelopeWrapper =
            serde_json::from_value(request.reencrypted_revisions[0].envelope.clone()).unwrap();
        let item_aad = AadV1::item(vault_id.to_string(), item_id.to_string(), 2, "login");
        let decrypted = decrypt_item(&new_vault_key, &item_aad, &wrapper.crypto).unwrap();
        let rotated_plaintext: ItemPlaintextV1 = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(rotated_plaintext.title, "GitHub");
    }

    #[test]
    fn rotation_request_rejects_member_from_other_vault() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let other_vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let member_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let old_vault_key = generate_vault_key();
        let new_vault_key = generate_vault_key();
        let member_keys = generate_user_keypair();
        let member = VaultMemberResponse {
            vault_id: other_vault_id,
            user_id: member_id,
            role: VaultRole::Editor,
            state: MemberState::Active,
            public_key: member_keys.public_key.to_base64url(),
        };

        let result = build_rotation_request(
            vault_id,
            1,
            &old_vault_key,
            &new_vault_key,
            &[member],
            &[],
            RotationCacheSnapshot::full_vault([]),
        );

        assert!(matches!(
            result,
            Err(CliError::Input(
                "vault member response does not belong to selected vault"
            ))
        ));
    }

    #[test]
    fn rotation_request_rejects_incomplete_item_snapshot() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let member_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let missing_item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let old_vault_key = generate_vault_key();
        let new_vault_key = generate_vault_key();
        let member_keys = generate_user_keypair();
        let plaintext = ItemPlaintextV1 {
            schema_version: 1,
            title: "GitHub".to_owned(),
            fields: vec![],
            notes: Some("rotated".to_owned()),
            tags: vec![],
        };
        let envelope = encrypt_item_plaintext(
            vault_id,
            item_id,
            1,
            "login".to_owned(),
            &old_vault_key,
            &plaintext,
        )
        .unwrap();
        let revision = crate::cache::CachedItemRevision {
            vault_id,
            item_id,
            revision: 1,
            vault_revision: 1,
            key_generation: 1,
            author_user_id: None,
            envelope,
        };
        let member = VaultMemberResponse {
            vault_id,
            user_id: member_id,
            role: VaultRole::Editor,
            state: MemberState::Active,
            public_key: member_keys.public_key.to_base64url(),
        };

        let result = build_rotation_request(
            vault_id,
            1,
            &old_vault_key,
            &new_vault_key,
            &[member],
            &[revision],
            RotationCacheSnapshot::full_vault([item_id, missing_item_id]),
        );

        assert!(matches!(
            result,
            Err(CliError::Input(
                "cached item snapshot is incomplete; run a full sync and try again"
            ))
        ));
    }

    #[test]
    fn rotation_request_rejects_stale_item_generation() {
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let member_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let old_vault_key = generate_vault_key();
        let new_vault_key = generate_vault_key();
        let member_keys = generate_user_keypair();
        let plaintext = ItemPlaintextV1 {
            schema_version: 1,
            title: "GitHub".to_owned(),
            fields: vec![],
            notes: Some("rotated".to_owned()),
            tags: vec![],
        };
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let envelope = encrypt_item_plaintext(
            vault_id,
            item_id,
            1,
            "login".to_owned(),
            &old_vault_key,
            &plaintext,
        )
        .unwrap();
        let revision = crate::cache::CachedItemRevision {
            vault_id,
            item_id,
            revision: 1,
            vault_revision: 1,
            key_generation: 2,
            author_user_id: None,
            envelope,
        };
        let member = VaultMemberResponse {
            vault_id,
            user_id: member_id,
            role: VaultRole::Editor,
            state: MemberState::Active,
            public_key: member_keys.public_key.to_base64url(),
        };

        let result = build_rotation_request(
            vault_id,
            1,
            &old_vault_key,
            &new_vault_key,
            &[member],
            &[revision],
            RotationCacheSnapshot::full_vault([item_id]),
        );

        match result {
            Err(CliError::Input(message)) => {
                assert!(message.contains("cached item generation is stale"));
            }
            other => panic!("expected stale generation error, got {other:?}"),
        }
    }

    #[test]
    fn save_pending_login_crypto_material_stores_encrypted_private_key() {
        let mut profile = crate::config::ProfileConfig::default();
        let encrypted_private_key = serde_json::json!({
            "version": 1,
            "suite": "UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1",
            "nonce": "nonce",
            "aad": "aad",
            "ciphertext": "ciphertext"
        });

        save_pending_login_crypto_material(&mut profile, encrypted_private_key.clone());

        assert_eq!(
            profile.encrypted_user_private_key.as_ref(),
            Some(&encrypted_private_key)
        );
        assert_eq!(profile.user_secret_key, None);
        assert_eq!(profile.kdf_params, None);
        assert_eq!(profile.client_public_key, None);
    }

    #[test]
    fn emergency_kit_from_profile_omits_encrypted_private_key() {
        let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&MasterPassword::new(
            "correct horse battery staple",
        ))
        .unwrap();
        let profile = crate::config::ProfileConfig {
            email: Some("miguel@example.com".to_owned()),
            client_public_key: Some(account_crypto.public_key.to_base64url()),
            encrypted_user_private_key: Some(
                serde_json::to_value(account_crypto.encrypted_private_key).unwrap(),
            ),
            kdf_params: Some(account_crypto.kdf_params.clone()),
            user_secret_key: Some(account_crypto.user_secret_key.to_base64url()),
            ..crate::config::ProfileConfig::default()
        };

        let kit = emergency_kit_json_from_profile(&profile).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&kit).unwrap();

        assert_emergency_kit_json(
            &parsed,
            "miguel@example.com",
            &account_crypto.public_key.to_base64url(),
            &account_crypto.user_secret_key.to_base64url(),
        );
        assert!(kit.contains("miguel@example.com"));
        assert!(kit.contains(&account_crypto.public_key.to_base64url()));
        assert!(kit.contains(&account_crypto.user_secret_key.to_base64url()));
        assert!(!kit.contains("encrypted_private_key"));
        assert!(!kit.contains("private_key"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn emergency_kit_export_command_writes_active_profile_kit() {
        let inactive_crypto = crate::crypto_state::NewAccountCrypto::generate(
            &MasterPassword::new("inactive profile password"),
        )
        .unwrap();
        let active_crypto = crate::crypto_state::NewAccountCrypto::generate(&MasterPassword::new(
            "active profile password",
        ))
        .unwrap();
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "default".to_owned(),
            crate::config::ProfileConfig {
                email: Some("default@example.com".to_owned()),
                client_public_key: Some(inactive_crypto.public_key.to_base64url()),
                encrypted_user_private_key: Some(
                    serde_json::to_value(inactive_crypto.encrypted_private_key).unwrap(),
                ),
                kdf_params: Some(inactive_crypto.kdf_params),
                user_secret_key: Some(inactive_crypto.user_secret_key.to_base64url()),
                ..crate::config::ProfileConfig::default()
            },
        );
        profiles.insert(
            "work".to_owned(),
            crate::config::ProfileConfig {
                email: Some("work@example.com".to_owned()),
                client_public_key: Some(active_crypto.public_key.to_base64url()),
                encrypted_user_private_key: Some(
                    serde_json::to_value(active_crypto.encrypted_private_key).unwrap(),
                ),
                kdf_params: Some(active_crypto.kdf_params.clone()),
                user_secret_key: Some(active_crypto.user_secret_key.to_base64url()),
                ..crate::config::ProfileConfig::default()
            },
        );
        let config = CliConfig {
            active_profile: "work".to_owned(),
            profiles,
            server_url: None,
            session_token: None,
        };
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("umbra-emergency-kit.json");
        // This command consults checkpoint trust anchors from the local cache.
        // Keep the test independent of the interactive user's data directory.
        unsafe { std::env::set_var("UMBRA_CACHE_DIR", temp.path()) };

        run(
            Command::EmergencyKit(EmergencyKitCommand::Export {
                output: Some(output.clone()),
            }),
            config,
            OutputMode::Human,
        )
        .await
        .unwrap();

        let kit = std::fs::read_to_string(output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&kit).unwrap();
        assert_emergency_kit_json(
            &parsed,
            "work@example.com",
            &active_crypto.public_key.to_base64url(),
            &active_crypto.user_secret_key.to_base64url(),
        );
        assert!(!kit.contains("default@example.com"));
        assert!(!kit.contains(&inactive_crypto.public_key.to_base64url()));
        assert!(!kit.contains("encrypted_private_key"));
        assert!(!kit.contains("private_key"));
        unsafe { std::env::remove_var("UMBRA_CACHE_DIR") };
    }

    #[test]
    fn apply_recovered_emergency_kit_material_saves_profile_crypto() {
        let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&MasterPassword::new(
            "correct horse battery staple",
        ))
        .unwrap();
        let kit = crate::crypto_state::EmergencyKitV1::from_account_crypto(None, &account_crypto);
        let mut profile = crate::config::ProfileConfig {
            pending_approval_code: Some("UMBRA-ABCD-1234".to_owned()),
            legacy_session_token: Some("pending-bearer".to_owned()),
            session_id: Some(uuid::Uuid::new_v4()),
            encrypted_user_private_key: Some(
                serde_json::to_value(account_crypto.encrypted_private_key.clone()).unwrap(),
            ),
            ..crate::config::ProfileConfig::default()
        };

        apply_recovered_emergency_kit_material(&mut profile, &kit).unwrap();

        assert_eq!(
            profile.client_public_key.as_deref(),
            Some(account_crypto.public_key.to_base64url().as_str())
        );
        assert_eq!(
            profile.user_secret_key.as_deref(),
            Some(account_crypto.user_secret_key.to_base64url().as_str())
        );
        assert_eq!(
            profile.kdf_params.as_ref(),
            Some(&account_crypto.kdf_params)
        );
        assert_eq!(profile.pending_approval_code, None);
        assert_eq!(profile.legacy_session_token, None);
        assert_eq!(profile.session_id, None);
    }

    #[test]
    fn emergency_kit_restores_authenticated_checkpoint_anchors_after_recovery() {
        let password = MasterPassword::new("correct horse battery staple");
        let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&password).unwrap();
        let unlocked = account_crypto.unlock(&password).unwrap();
        let signing_key = crate::keys::DeviceSigningKey::generate();
        let source_anchor = crate::cache::TrustedCheckpointDevice {
            device_id: uuid::Uuid::from_u128(1),
            public_key: signing_key.public_key_base64url(),
            revoked: false,
        };
        let bundle =
            authenticated_checkpoint_trust_bundle(&unlocked, std::slice::from_ref(&source_anchor))
                .unwrap();
        let mut kit =
            crate::crypto_state::EmergencyKitV1::from_account_crypto(None, &account_crypto);
        kit.checkpoint_trust_bundle = Some(bundle);
        let recovered_anchors = checkpoint_anchors_from_emergency_kit(&unlocked, &kit).unwrap();
        let recovered_cache = crate::cache::LocalCache::open_in_memory("recovered-device").unwrap();

        record_checkpoint_trust_anchors(&recovered_cache, &recovered_anchors).unwrap();

        assert_eq!(
            recovered_cache.trusted_checkpoint_devices().unwrap(),
            vec![source_anchor]
        );
    }

    #[test]
    fn signed_anchor_export_import_migrates_existing_devices_without_secrets() {
        let password = MasterPassword::new("correct horse battery staple");
        let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&password).unwrap();
        let unlocked = account_crypto.unlock(&password).unwrap();
        let device_signing_key = crate::keys::DeviceSigningKey::generate();
        let anchor = crate::cache::TrustedCheckpointDevice {
            device_id: uuid::Uuid::from_u128(2),
            public_key: device_signing_key.public_key_base64url(),
            revoked: false,
        };
        let source = crate::cache::LocalCache::open_in_memory("existing-source").unwrap();
        source.record_trusted_checkpoint_device(&anchor).unwrap();
        let bundle = authenticated_checkpoint_trust_bundle(
            &unlocked,
            &source.trusted_checkpoint_devices().unwrap(),
        )
        .unwrap();
        let encoded = serde_json::to_string(&bundle).unwrap();
        let destination = crate::cache::LocalCache::open_in_memory("existing-destination").unwrap();

        import_checkpoint_trust_bundle(&destination, &unlocked, &bundle).unwrap();

        assert_eq!(
            destination.trusted_checkpoint_devices().unwrap(),
            vec![anchor]
        );
        assert!(!encoded.contains(&account_crypto.user_secret_key.to_base64url()));
        assert!(!encoded.contains(&unlocked.private_key.to_base64url()));
        assert!(!encoded.contains(&device_signing_key.to_base64url()));
        assert!(!encoded.contains("ciphertext"));
        assert!(!encoded.contains("vault_key"));
        assert!(!encoded.contains("envelope"));
    }

    #[test]
    fn anchor_import_rejects_tampering_before_mutating_cache() {
        let password = MasterPassword::new("correct horse battery staple");
        let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&password).unwrap();
        let unlocked = account_crypto.unlock(&password).unwrap();
        let signing_key = crate::keys::DeviceSigningKey::generate();
        let anchor = crate::cache::TrustedCheckpointDevice {
            device_id: uuid::Uuid::from_u128(3),
            public_key: signing_key.public_key_base64url(),
            revoked: false,
        };
        let mut bundle = authenticated_checkpoint_trust_bundle(&unlocked, &[anchor]).unwrap();
        bundle.trusted_checkpoint_devices[0].revoked = true;
        let destination = crate::cache::LocalCache::open_in_memory("tampered").unwrap();

        assert!(import_checkpoint_trust_bundle(&destination, &unlocked, &bundle).is_err());
        assert!(destination.trusted_checkpoint_devices().unwrap().is_empty());
    }

    #[tokio::test]
    async fn device_recover_requires_emergency_kit() {
        let mut config = CliConfig::default();
        active_profile_mut(&mut config).device_id = Some(uuid::Uuid::new_v4());

        let result = run(
            Command::Device(DeviceCommand::Recover {
                device_id: None,
                emergency_kit: None,
            }),
            config,
            OutputMode::Human,
        )
        .await;

        assert!(matches!(
            result,
            Err(CliError::Input(
                "pass --emergency-kit <path> for clean-device recovery"
            ))
        ));
    }

    fn assert_emergency_kit_json(
        parsed: &serde_json::Value,
        email: &str,
        account_public_key: &str,
        user_secret_key: &str,
    ) {
        let object = parsed.as_object().unwrap();
        let keys = object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "account_public_key",
                "email",
                "kdf_params",
                "user_secret_key",
                "version"
            ])
        );
        assert_eq!(
            object.get("version").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            object.get("email").and_then(serde_json::Value::as_str),
            Some(email)
        );
        assert_eq!(
            object
                .get("account_public_key")
                .and_then(serde_json::Value::as_str),
            Some(account_public_key)
        );
        assert_eq!(
            object
                .get("user_secret_key")
                .and_then(serde_json::Value::as_str),
            Some(user_secret_key)
        );
        assert!(
            object
                .get("kdf_params")
                .and_then(serde_json::Value::as_object)
                .is_some()
        );
    }

    #[test]
    fn device_bootstrap_bundle_reads_profile_crypto_material() {
        let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&MasterPassword::new(
            "correct horse battery staple",
        ))
        .unwrap();
        let default_vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let profile = crate::config::ProfileConfig {
            client_public_key: Some(account_crypto.public_key.to_base64url()),
            encrypted_user_private_key: Some(
                serde_json::to_value(account_crypto.encrypted_private_key).unwrap(),
            ),
            kdf_params: Some(account_crypto.kdf_params.clone()),
            user_secret_key: Some(account_crypto.user_secret_key.to_base64url()),
            default_vault_id: Some(default_vault_id),
            ..crate::config::ProfileConfig::default()
        };

        let anchors = vec![crate::cache::TrustedCheckpointDevice {
            device_id: Uuid::from_u128(9),
            public_key: "checkpoint-public-key".to_owned(),
            revoked: false,
        }];
        let bundle = device_bootstrap_bundle_from_profile(&profile, &anchors).unwrap();

        assert_eq!(bundle.version, 1);
        assert_eq!(
            bundle.account_public_key,
            account_crypto.public_key.to_base64url()
        );
        let expected_default_vault_id = default_vault_id.to_string();
        assert_eq!(
            bundle.default_vault_id.as_deref(),
            Some(expected_default_vault_id.as_str())
        );
        assert_eq!(bundle.trusted_checkpoint_devices.len(), 1);
        assert_eq!(
            bundle.trusted_checkpoint_devices[0].device_id,
            Uuid::from_u128(9).to_string()
        );
        assert_eq!(
            bundle.trusted_checkpoint_devices[0].public_key,
            "checkpoint-public-key"
        );
    }

    #[test]
    fn encrypted_bootstrap_transfers_checkpoint_anchors_to_second_device() {
        let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&MasterPassword::new(
            "correct horse battery staple",
        ))
        .unwrap();
        let first_key = DeviceSigningKey::generate();
        let second_key = DeviceSigningKey::generate();
        let first_device = Uuid::from_u128(9);
        let second_device = Uuid::from_u128(10);
        let anchors = vec![
            crate::cache::TrustedCheckpointDevice {
                device_id: first_device,
                public_key: first_key.public_key_base64url(),
                revoked: false,
            },
            crate::cache::TrustedCheckpointDevice {
                device_id: second_device,
                public_key: second_key.public_key_base64url(),
                revoked: false,
            },
        ];
        let profile = crate::config::ProfileConfig {
            client_public_key: Some(account_crypto.public_key.to_base64url()),
            encrypted_user_private_key: Some(
                serde_json::to_value(account_crypto.encrypted_private_key).unwrap(),
            ),
            kdf_params: Some(account_crypto.kdf_params.clone()),
            user_secret_key: Some(account_crypto.user_secret_key.to_base64url()),
            ..crate::config::ProfileConfig::default()
        };
        let bundle = device_bootstrap_bundle_from_profile(&profile, &anchors).unwrap();
        let bootstrap_keypair = generate_user_keypair();
        let aad = AadV1::device_bootstrap(second_device.to_string());
        let envelope =
            encrypt_device_bootstrap_bundle(&bootstrap_keypair.public_key, aad.clone(), &bundle)
                .unwrap();
        let decrypted =
            decrypt_device_bootstrap_bundle(&bootstrap_keypair.private_key, &aad, &envelope)
                .unwrap();
        let second_cache = crate::cache::LocalCache::open_in_memory("second-device").unwrap();
        for anchor in &decrypted.trusted_checkpoint_devices {
            second_cache
                .record_trusted_checkpoint_device(
                    &checkpoint_anchor_from_bootstrap(anchor).unwrap(),
                )
                .unwrap();
        }

        assert_eq!(second_cache.trusted_checkpoint_devices().unwrap(), anchors);
    }

    #[test]
    fn vault_kind_label_uses_cli_names() {
        assert_eq!(vault_kind_label(VaultKind::Personal), "personal");
        assert_eq!(vault_kind_label(VaultKind::Shared), "shared");
        assert_eq!(vault_kind_label(VaultKind::Project), "project");
        assert_eq!(vault_kind_label(VaultKind::Org), "org");
    }

    #[test]
    fn render_vault_created_accepts_json_and_human_modes() {
        let vault = VaultResponse {
            vault_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            org_id: None,
            name: "Personal".to_owned(),
            kind: VaultKind::Personal,
            vault_revision: 1,
            access_revision: 2,
            current_key_generation: 1,
            needs_key_rotation: false,
        };

        assert!(render_vault_created(OutputMode::Json, &vault).is_ok());
        assert!(render_vault_created(OutputMode::Human, &vault).is_ok());
    }

    #[test]
    fn render_devices_accepts_json_and_human_modes() {
        let devices = vec![DeviceResponse {
            device_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            name: "Laptop".to_owned(),
            public_key: Some("device-public-key".to_owned()),
            encryption_public_key: Some("device-encryption-public-key".to_owned()),
            fingerprint: "SHA256:test".to_owned(),
            state: umbra_core::DeviceState::Trusted,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            trusted_at: Some("2026-01-01T00:00:00Z".to_owned()),
            revoked_at: None,
        }];

        assert!(render_devices(OutputMode::Json, &devices).is_ok());
        assert!(render_devices(OutputMode::Human, &devices).is_ok());
    }

    #[test]
    fn render_item_revision_created_accepts_json_and_human_modes() {
        let response = ItemRevisionResponse {
            item_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            vault_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            revision: 3,
            vault_revision: 4,
            key_generation: 1,
            author_user_id: None,
            envelope: serde_json::json!({"kind": "login"}),
        };

        assert!(render_item_revision_created(OutputMode::Json, "created item", &response).is_ok());
        assert!(render_item_revision_created(OutputMode::Human, "created item", &response).is_ok());
    }

    #[test]
    fn resolve_vault_id_accepts_uuid_string_vault_selector() {
        let profile = crate::config::ProfileConfig::default();
        let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        assert_eq!(
            resolve_vault_id(&profile, &cache, None, Some(&vault_id.to_string())).unwrap(),
            vault_id
        );
    }

    #[test]
    fn resolve_vault_id_keeps_json_mode_non_interactive() {
        let profile = crate::config::ProfileConfig::default();
        let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();

        assert!(matches!(
            resolve_vault_id_for_output(&profile, &cache, None, None, OutputMode::Json),
            Err(CliError::Input(
                "no default vault configured; pass --vault-id/--vault or create a vault first"
            ))
        ));
    }

    #[test]
    fn pre_unlock_item_selector_rejects_both_selectors() {
        let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();

        assert!(matches!(
            select_cached_item_revision_before_unlock_for_output(
                &cache,
                vault_id,
                Some(item_id),
                Some("GitHub"),
                OutputMode::Human,
            ),
            Err(CliError::Input("use either --item-id or --title, not both"))
        ));
    }

    #[test]
    fn pre_unlock_item_selector_allows_missing_selector_in_human_mode() {
        let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        assert!(matches!(
            select_cached_item_revision_before_unlock_for_output(
                &cache,
                vault_id,
                None,
                None,
                OutputMode::Human
            ),
            Ok(ItemSelectionNeed::NeedsInteractiveDecrypt)
        ));
    }

    #[test]
    fn item_selector_requires_selector_in_json_mode() {
        let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        assert!(matches!(
            select_cached_item_revision_before_unlock_for_output(
                &cache,
                vault_id,
                None,
                None,
                OutputMode::Json
            ),
            Err(CliError::Input("pass --item-id or --title"))
        ));
    }

    #[test]
    fn pre_unlock_item_selector_rejects_missing_item_id() {
        let cache = crate::cache::LocalCache::open_in_memory("personal").unwrap();
        let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();

        assert!(matches!(
            select_cached_item_revision_before_unlock_for_output(
                &cache,
                vault_id,
                Some(item_id),
                None,
                OutputMode::Human,
            ),
            Err(CliError::Input("cached item not found"))
        ));
    }

    #[test]
    fn listed_secret_bundle_omits_secret_values() {
        let mut plaintext =
            crate::item_plaintext::build_secret_bundle("umbra/prod", "DATABASE_URL", "secret");
        crate::item_plaintext::set_plaintext_field(
            &mut plaintext,
            "FEATURE_FLAG",
            "enabled".to_owned(),
        );

        let bundle = listed_secret_bundle(&plaintext);
        let value = serde_json::to_value(&bundle).unwrap();

        assert_eq!(bundle.project_env, "umbra/prod");
        assert_eq!(bundle.fields.len(), 2);
        assert_eq!(bundle.fields[0].key, "DATABASE_URL");
        assert_eq!(bundle.fields[0].kind, "Secret");
        assert!(bundle.fields[0].sensitive);
        assert_eq!(bundle.fields[1].key, "FEATURE_FLAG");
        assert_eq!(bundle.fields[1].kind, "Text");
        assert!(!bundle.fields[1].sensitive);
        assert!(value.get("fields").is_some());
        assert!(value.to_string().contains("DATABASE_URL"));
        assert!(!value.to_string().contains("secret"));
        assert!(!value.to_string().contains("enabled"));
        assert!(!value.to_string().contains("value"));
    }

    #[test]
    fn env_get_json_payload_uses_sorted_variables() {
        let mut plaintext = crate::item_plaintext::build_secret_bundle(
            "pulzar/dev",
            "DATABASE_URL",
            "postgres://localhost",
        );
        crate::item_plaintext::set_plaintext_field(
            &mut plaintext,
            "OPENAI_API_KEY",
            "sk-test".to_owned(),
        );

        let variables = env_variables_json(&plaintext);

        assert_eq!(
            variables.keys().cloned().collect::<Vec<_>>(),
            vec!["DATABASE_URL".to_owned(), "OPENAI_API_KEY".to_owned()]
        );
        assert_eq!(
            variables.get("DATABASE_URL").map(String::as_str),
            Some("postgres://localhost")
        );
    }

    #[test]
    fn env_file_writer_writes_requested_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");

        write_env_file(&path, "DATABASE_URL=postgres://localhost\n", false).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "DATABASE_URL=postgres://localhost\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_file_writer_creates_owner_only_files_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");

        write_env_file(&path, "SECRET=value\n", false).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn env_file_writer_refuses_existing_file_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "DATABASE_URL=old\n").unwrap();

        let result = write_env_file(&path, "DATABASE_URL=new\n", false);

        assert!(matches!(result, Err(CliError::Input(_))));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "DATABASE_URL=old\n"
        );
    }

    #[test]
    fn sync_integrity_export_writer_refuses_overwrite_and_uses_safe_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.json");
        let vault_id = uuid::Uuid::from_u128(1);
        let bundle = crate::cache::CheckpointForensicsBundle {
            version: 1,
            vault_id,
            unsafe_sync: true,
            verified_checkpoints: vec![],
            observed_checkpoints: vec![],
            findings: vec![crate::cache::IntegrityFinding {
                vault_id,
                revision: 3,
                checkpoint_hash: "public-checkpoint-id".to_owned(),
                code: "equivocation".to_owned(),
                conflicting_checkpoint_hash: Some("other-public-checkpoint-id".to_owned()),
                observed_at: "2026-07-24T00:00:00Z".to_owned(),
            }],
        };

        write_forensics_bundle(&path, &bundle).unwrap();
        let encoded = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["vault_id"], vault_id.to_string());
        assert_eq!(value["findings"][0]["code"], "equivocation");
        for forbidden in [
            "envelope",
            "plaintext",
            "wrapping",
            "token",
            "private_key",
            "vault_key",
        ] {
            assert!(!encoded.contains(forbidden));
        }

        let result = write_forensics_bundle(&path, &bundle);
        assert!(matches!(
            result,
            Err(CliError::Input(
                "integrity export destination already exists"
            ))
        ));
    }

    #[test]
    fn env_file_writer_overwrites_existing_file_when_requested() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "DATABASE_URL=old\n").unwrap();

        write_env_file(&path, "DATABASE_URL=new\n", true).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "DATABASE_URL=new\n"
        );
    }

    #[test]
    fn env_file_writer_preserves_destination_and_removes_temp_when_replace_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::create_dir(&path).unwrap();

        let result = write_env_file(&path, "DATABASE_URL=new\n", true);

        assert!(result.is_err());
        assert!(path.is_dir());
        let temp_prefix = ".env.";
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(temp_prefix)
        }));
    }

    #[cfg(unix)]
    #[test]
    fn env_file_writer_overwrite_replaces_permissive_file_with_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "SECRET=old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_env_file(&path, "SECRET=new\n", true).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "SECRET=new\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn build_env_command_rejects_empty_command() {
        let result = build_env_command(&[], vec![("DATABASE_URL".to_owned(), "secret".to_owned())]);

        assert!(matches!(
            result,
            Err(CliError::Input("run requires a command after --"))
        ));
    }

    #[test]
    fn secret_key_selector_requires_key_in_json_mode() {
        let plaintext =
            crate::item_plaintext::build_secret_bundle("umbra/prod", "DATABASE_URL", "secret");

        assert!(matches!(
            resolve_secret_key_for_output(None, &plaintext, OutputMode::Json),
            Err(CliError::Input("pass a secret key"))
        ));
    }

    #[test]
    fn listed_secret_rows_omit_secret_values() {
        let mut plaintext =
            crate::item_plaintext::build_secret_bundle("umbra/prod", "DATABASE_URL", "secret");
        crate::item_plaintext::set_plaintext_field(
            &mut plaintext,
            "FEATURE_FLAG",
            "enabled".to_owned(),
        );

        let bundle = listed_secret_bundle(&plaintext);
        let rows = listed_secret_rows(&bundle);

        assert_eq!(
            rows,
            vec![
                vec![
                    "DATABASE_URL".to_owned(),
                    "Secret".to_owned(),
                    "yes".to_owned(),
                ],
                vec![
                    "FEATURE_FLAG".to_owned(),
                    "Text".to_owned(),
                    "no".to_owned(),
                ],
            ]
        );
        assert!(!format!("{rows:?}").contains("secret"));
        assert!(!format!("{rows:?}").contains("enabled"));
    }
}
