use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use umbra_core::{ItemKind, ItemPlaintextV1, VaultId, VaultKind};
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, DeviceBootstrapBundleV1, DeviceBootstrapEnvelopeV1, MasterPassword,
    RecoveryChallengeEnvelopeV1, UserPrivateKey, UserPublicKey, VaultKey,
    VaultKeyWrappingEnvelopeV1, decrypt_device_bootstrap_bundle, decrypt_item,
    decrypt_recovery_challenge, encrypt_device_bootstrap_bundle, encrypt_item,
    generate_user_keypair, generate_vault_key, unwrap_vault_key, wrap_vault_key_for_user,
};
use umbra_protocol::{
    ApprovalLookupRequest, ApproveDeviceRequest, CreateItemRequest, CreateVaultRequest,
    DeviceBootstrapResponse, DeviceResponse, ItemRevisionResponse, PROTOCOL_VERSION,
    PendingDeviceSummary, RecoverTrustRequest, RecoverTrustResponse, RecoveryChallengeStartRequest,
    RecoveryChallengeStartResponse, SyncRequest, SyncResponse, UpdateItemRequest, VaultResponse,
    VaultSyncCursor,
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
    AuthCommand, CacheCommand, Command, DeviceCommand, EmergencyKitCommand, ItemCommand,
    ProfileCommand, SecretCommand, SyncCommand, TokenCommand, VaultCommand,
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

pub async fn run(
    command: Command,
    mut config: CliConfig,
    output: OutputMode,
) -> Result<(), CliError> {
    match command {
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
                },
            )
            .await?;
            let profile_config = active_profile_mut(&mut config);
            profile_config.server_url = server;
            profile_config.email = Some(email);
            profile_config.user_id = Some(response.user_id);
            profile_config.device_id = Some(response.device_id);
            profile_config.device_private_key = Some(device_key.to_base64url());
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

            let password = rpassword::prompt_password("Master password: ")?;
            let unlocked = crate::crypto_state::load_unlocked_profile(
                profile,
                &MasterPassword::new(password.into_bytes()),
            )?;
            let mut vault_keys = BTreeMap::new();
            for vault_id in vault_ids {
                let wrapping = cache
                    .latest_key_wrapping(vault_id, user_id)?
                    .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
                let envelope: VaultKeyWrappingEnvelopeV1 =
                    serde_json::from_value(wrapping.envelope)?;
                let aad = AadV1::vault_key_wrapping(vault_id.to_string());
                let vault_key = unwrap_vault_key(&unlocked.private_key, &aad, &envelope)?;
                vault_keys.insert(vault_id, vault_key);
            }

            let state = crate::unlock_store::UnlockedLocalState::new(
                profile_name.clone(),
                user_id,
                device_id,
                chrono::Utc::now() + chrono::Duration::minutes(ttl_minutes),
                unlocked.private_key,
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
        Command::EmergencyKit(EmergencyKitCommand::Export { output }) => {
            let profile = active_profile(&config)?;
            let encoded = emergency_kit_json_from_profile(profile)?;
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
            let bootstrap_bundle = if let Some(raw) = bootstrap_bundle_json {
                serde_json::from_str(&raw)?
            } else {
                let recipient = UserPublicKey::from_base64url(&pending.bootstrap_public_key)?;
                let bundle = device_bootstrap_bundle_from_profile(profile)?;
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
            if emergency_kit.is_some() {
                return Err(CliError::Input(
                    "emergency kit recovery is not implemented yet",
                ));
            }
            let profile = active_profile_mut(&mut config);
            let device_id = device_id
                .or(profile.device_id)
                .ok_or(CliError::Input("profile has no pending device id"))?;
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
            let unlocked = crate::crypto_state::load_unlocked_profile(
                profile,
                &MasterPassword::new(password.into_bytes()),
            )?;
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
            profile.pending_approval_code = None;
            save_config(&config)?;
            if output.is_json() {
                print_json(&recovered)
            } else {
                println!("recovered device trust: {}", recovered.device_id);
                Ok(())
            }
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
            let requested_vault_id = Uuid::new_v4();
            let initial_key_wrapping = match wrapping_json {
                Some(value) => serde_json::from_str(&value)?,
                None => {
                    let public_key = profile_public_key(profile)?;
                    let vault_key = generate_vault_key();
                    let aad = AadV1::vault_key_wrapping(requested_vault_id.to_string());
                    let wrapping = wrap_vault_key_for_user(&public_key, &vault_key, aad)?;
                    serde_json::to_value(wrapping)?
                }
            };
            let vault: VaultResponse = client
                .post(
                    "/api/v1/vaults",
                    &CreateVaultRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id: Some(requested_vault_id),
                        name,
                        kind: VaultKind::Personal,
                        initial_key_wrapping,
                    },
                )
                .await?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            cache.upsert_vault(&vault)?;
            let profile_config = active_profile_mut(&mut config);
            if profile_config.default_vault_id.is_none() {
                profile_config.default_vault_id = Some(vault.vault_id);
                save_config(&config)?;
            }
            let profile = active_profile(&config)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault.vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
            render_vault_created(output, &vault)
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
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
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
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            cache.upsert_item_revision(&response)?;
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
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
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
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
            crate::sync::ensure_vault_synced(
                profile,
                &mut cache,
                vault_id,
                crate::sync::SyncMode::Always,
            )
            .await?;
            if output.is_json() {
                print_json(&response)
            } else {
                println!("removed {key} from {project_env}");
                Ok(())
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
            let since_vault_revision = if force_full {
                0
            } else if let Some(value) = since_vault_revision {
                value
            } else {
                cache
                    .sync_state(vault_id)?
                    .map(|state| state.latest_vault_revision)
                    .unwrap_or(0)
            };
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
            for vault in &response.vaults {
                cache.apply_sync_changes(vault)?;
            }
            render_sync_response(output, &response)
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

fn profile_public_key(profile: &crate::config::ProfileConfig) -> Result<UserPublicKey, CliError> {
    let public_key = profile.client_public_key.as_deref().ok_or(CliError::Input(
        "profile has no account public key; run `umbra register` for this profile",
    ))?;
    Ok(UserPublicKey::from_base64url(public_key)?)
}

fn emergency_kit_json_from_profile(
    profile: &crate::config::ProfileConfig,
) -> Result<String, CliError> {
    let kit = crate::crypto_state::EmergencyKitV1::from_profile(profile)?;
    serde_json::to_string_pretty(&kit).map_err(CliError::from)
}

fn device_bootstrap_bundle_from_profile(
    profile: &crate::config::ProfileConfig,
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

fn vault_kind_label(kind: VaultKind) -> &'static str {
    match kind {
        VaultKind::Personal => "personal",
        VaultKind::Shared => "shared",
        VaultKind::Project => "project",
        VaultKind::Org => "org",
    }
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
    let password = rpassword::prompt_password("Master password: ")?;
    let unlocked = crate::crypto_state::load_unlocked_profile(
        profile,
        &MasterPassword::new(password.into_bytes()),
    )?;
    let wrapping = cache
        .latest_key_wrapping(vault_id, user_id)?
        .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
    let envelope: VaultKeyWrappingEnvelopeV1 = serde_json::from_value(wrapping.envelope)?;
    let aad = AadV1::vault_key_wrapping(vault_id.to_string());

    unwrap_vault_key(&unlocked.private_key, &aad, &envelope).map_err(CliError::from)
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
        wrapper.kind,
    );
    let plaintext = decrypt_item(vault_key, &aad, &wrapper.crypto)?;

    Ok(DecryptedCachedItem {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[tokio::test]
    async fn device_recover_rejects_emergency_kit_until_implemented() {
        let result = run(
            Command::Device(DeviceCommand::Recover {
                device_id: None,
                emergency_kit: Some("umbra-emergency-kit.json".into()),
            }),
            CliConfig::default(),
            OutputMode::Human,
        )
        .await;

        assert!(matches!(
            result,
            Err(CliError::Input(
                "emergency kit recovery is not implemented yet"
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

        let bundle = device_bootstrap_bundle_from_profile(&profile).unwrap();

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
