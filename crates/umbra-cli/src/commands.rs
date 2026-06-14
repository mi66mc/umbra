use serde_json::Value;
use umbra_core::{ItemKind, VaultKind};
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
    AuthCommand, CacheCommand, Command, ItemCommand, ProfileCommand, SyncCommand, TokenCommand,
    VaultCommand,
};

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
            let client = PublicHttpClient::new(&server)?;
            let response = crate::opaque::register(
                &client,
                &email,
                display_name,
                password.as_bytes(),
                &device_name,
                &device_key,
            )
            .await?;
            let profile_config = active_profile_mut(&mut config);
            profile_config.server_url = server;
            profile_config.email = Some(email);
            profile_config.user_id = Some(response.user_id);
            profile_config.device_id = Some(response.device_id);
            profile_config.device_private_key = Some(device_key.to_base64url());
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
            let wrapping_json = match wrapping_json {
                Some(value) => value,
                None => dialoguer::Input::<String>::new()
                    .with_prompt("Initial vault key wrapping JSON")
                    .interact_text()?,
            };
            let vault: VaultResponse = client
                .post(
                    "/api/v1/vaults",
                    &CreateVaultRequest {
                        protocol_version: PROTOCOL_VERSION,
                        name,
                        kind: VaultKind::Personal,
                        initial_key_wrapping: serde_json::from_str(&wrapping_json)?,
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
            print_json(&revision)
        }
        Command::Item(ItemCommand::Create {
            vault_id,
            kind,
            envelope_json,
        }) => {
            let profile = active_profile(&config)?;
            require_login(profile)?;
            let client = UmbraHttpClient::new(profile)?;
            let response: Value = client
                .post(
                    &format!("/api/v1/vaults/{vault_id}/items"),
                    &CreateItemRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        kind,
                        envelope: serde_json::from_str(&envelope_json)?,
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
