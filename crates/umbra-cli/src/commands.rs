use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use umbra_core::{ItemKind, ItemPlaintextV1, VaultId, VaultKind};
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, MasterPassword, UserPublicKey, VaultKey, VaultKeyWrappingEnvelopeV1,
    decrypt_item, encrypt_item, generate_vault_key, unwrap_vault_key, wrap_vault_key_for_user,
};
use umbra_protocol::{
    CreateItemRequest, CreateVaultRequest, ItemRevisionResponse, PROTOCOL_VERSION, SyncRequest,
    SyncResponse, UpdateItemRequest, VaultResponse, VaultSyncCursor,
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
    AuthCommand, CacheCommand, Command, ItemCommand, ProfileCommand, SecretCommand, SyncCommand,
    TokenCommand, VaultCommand,
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
        Command::Login { profile, email } => {
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
            let device_id = profile_snapshot.device_id.ok_or(CliError::Input(
                "profile has no device id; run `umbra register` first",
            ))?;
            let password = rpassword::prompt_password("Master password: ")?;
            let client = PublicHttpClient::new(&profile_snapshot.server_url)?;
            let response =
                crate::opaque::login(&client, &email, password.as_bytes(), device_id).await?;
            let profile_config = active_profile_mut(&mut config);
            profile_config.email = Some(email);
            profile_config.user_id = Some(response.user_id);
            profile_config.session_id = Some(response.session_id);
            profile_config.legacy_session_token = response.session_token;
            save_config(&config)?;
            println!("logged in: {}", config.active_profile);
            Ok(())
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
            print_json(&vault)
        }
        Command::Item(ItemCommand::List {
            vault_id,
            vault,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
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
            print_json(&cache.list_latest_item_revisions(vault_id)?)
        }
        Command::Item(ItemCommand::Get {
            vault_id,
            vault,
            item_id,
            offline,
        }) => {
            let profile = active_profile(&config)?;
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
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
            let Some(revision) = cache.latest_item_revision(vault_id, item_id)? else {
                return Err(CliError::Input("cached item not found"));
            };
            let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
            let item = decrypt_cached_item(&vault_key, &revision)?;
            print_json(&item.plaintext)
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
            let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
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
            print_json(&response)
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
            let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
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
            let mut existing_bundle = None;
            for revision in cache.list_latest_item_revisions(vault_id)? {
                let Ok(wrapper) =
                    serde_json::from_value::<ItemEnvelopeWrapper>(revision.envelope.clone())
                else {
                    continue;
                };
                if wrapper.kind != kind_name {
                    continue;
                }
                let item = decrypt_cached_item_wrapper(&vault_key, &revision, wrapper)?;
                if item.plaintext.title == project_env {
                    existing_bundle = Some((revision, item.plaintext));
                    break;
                }
            }

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
            print_json(&response)
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
            let vault_id = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
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
            for revision in cache.list_latest_item_revisions(vault_id)? {
                let Ok(wrapper) =
                    serde_json::from_value::<ItemEnvelopeWrapper>(revision.envelope.clone())
                else {
                    continue;
                };
                if wrapper.kind != "env_bundle" {
                    continue;
                }
                let item = decrypt_cached_item_wrapper(&vault_key, &revision, wrapper)?;
                if item.plaintext.title != project_env {
                    continue;
                }
                if let Some(field) = item.plaintext.fields.iter().find(|field| field.name == key) {
                    println!("{}", field.value);
                    return Ok(());
                }
            }
            Err(CliError::Input("secret not found"))
        }
        Command::Sync(SyncCommand::Run {
            vault_id,
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

fn render_vaults(output: OutputMode, vaults: &[VaultResponse]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(&vaults);
    }

    let rows = vaults
        .iter()
        .map(|vault| {
            vec![
                vault.name.clone(),
                format!("{:?}", vault.kind),
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

struct DecryptedCachedItem {
    plaintext: ItemPlaintextV1,
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
}
