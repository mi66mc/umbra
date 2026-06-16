use serde::{Deserialize, Serialize};
use serde_json::Value;
use umbra_core::{ItemKind, ItemPlaintextV1, VaultId, VaultKind};
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, MasterPassword, VaultKey, VaultKeyWrappingEnvelopeV1, decrypt_item,
    encrypt_item, generate_vault_key, unwrap_vault_key, wrap_vault_key_for_user,
};
use umbra_protocol::{
    CreateItemRequest, CreateVaultRequest, PROTOCOL_VERSION, SyncRequest, SyncResponse,
    UpdateItemRequest, VaultResponse, VaultSyncCursor,
};
use uuid::Uuid;

use crate::config::{
    CliConfig, active_profile, active_profile_mut, save_config, set_active_profile,
};
use crate::error::CliError;
use crate::http::{PublicHttpClient, UmbraHttpClient};
use crate::keys::DeviceSigningKey;
use crate::output::print_json;
use crate::{
    AuthCommand, CacheCommand, Command, ItemCommand, ProfileCommand, SecretCommand, SyncCommand,
    TokenCommand, VaultCommand,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ItemEnvelopeWrapper {
    kind: String,
    crypto: CryptoEnvelopeV1,
}

pub async fn run(command: Command, mut config: CliConfig) -> Result<(), CliError> {
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
            print_json(&cache.status()?)
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
            print_json(&vaults)
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
                    let password = rpassword::prompt_password("Master password: ")?;
                    let unlocked = crate::crypto_state::load_unlocked_profile(
                        profile,
                        &MasterPassword::new(password.into_bytes()),
                    )?;
                    let vault_key = generate_vault_key();
                    let aad = AadV1::vault_key_wrapping(requested_vault_id.to_string());
                    let wrapping = wrap_vault_key_for_user(&unlocked.public_key, &vault_key, aad)?;
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
            print_json(&vault)
        }
        Command::Item(ItemCommand::List { vault_id, cached }) => {
            if !cached {
                return Err(CliError::Input(
                    "remote item list is not implemented yet; use --cached after sync",
                ));
            }
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            print_json(&cache.list_latest_item_revisions(vault_id)?)
        }
        Command::Item(ItemCommand::Get {
            vault_id,
            item_id,
            cached,
        }) => {
            if !cached {
                return Err(CliError::Input(
                    "remote item get is not implemented yet; use --cached after sync",
                ));
            }
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let Some(revision) = cache.latest_item_revision(vault_id, item_id)? else {
                return Err(CliError::Input("cached item not found"));
            };
            let profile = active_profile(&config)?;
            let vault_key = unlock_vault_key_from_cache(profile, &cache, vault_id)?;
            let item = decrypt_cached_item(&vault_key, &revision)?;
            print_json(&item.plaintext)
        }
        Command::Item(ItemCommand::Create {
            vault_id,
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
            let (item_id, envelope) = match envelope_json {
                Some(envelope_json) => (None, serde_json::from_str(&envelope_json)?),
                None => {
                    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
                    let vault_key = unlock_vault_key_from_cache(profile, &cache, vault_id)?;
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
            let response: Value = client
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
            let response: Value = client
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
            print_json(&response)
        }
        Command::Secret(SecretCommand::Set {
            project_env,
            key,
            value,
            vault_id,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let value = match value {
                Some(value) => value,
                None => rpassword::prompt_password("Value: ")?,
            };
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_key = unlock_vault_key_from_cache(profile, &cache, vault_id)?;
            let item_id = Uuid::new_v4();
            let kind = ItemKind::EnvBundle;
            let kind_name = item_kind_name(&kind);
            let plaintext = crate::item_plaintext::build_secret_bundle(&project_env, &key, &value);
            let envelope =
                encrypt_item_plaintext(vault_id, item_id, 1, kind_name, &vault_key, &plaintext)?;
            let response: Value = client
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
                .await?;
            print_json(&response)
        }
        Command::Secret(SecretCommand::Get {
            project_env,
            key,
            vault_id,
        }) => {
            let profile = active_profile(&config)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let vault_key = unlock_vault_key_from_cache(profile, &cache, vault_id)?;
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
            let device_id = profile.device_id.unwrap_or_else(Uuid::new_v4);
            let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let since_vault_revision = if force_full {
                0
            } else if let Some(value) = since_vault_revision {
                value
            } else {
                cache.latest_vault_revision(vault_id)?.unwrap_or(0)
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
            print_json(&response)
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

struct DecryptedCachedItem {
    plaintext: ItemPlaintextV1,
}

fn unlock_vault_key_from_cache(
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: VaultId,
) -> Result<VaultKey, CliError> {
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
