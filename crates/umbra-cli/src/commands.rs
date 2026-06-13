use serde_json::Value;
use umbra_core::{ItemKind, VaultKind};
use umbra_protocol::{
    CreateItemRequest, CreateVaultRequest, PROTOCOL_VERSION, SyncRequest, SyncResponse,
    UpdateItemRequest, VaultResponse, VaultSyncCursor,
};
use uuid::Uuid;

use crate::config::{CliConfig, save_config};
use crate::error::CliError;
use crate::http::UmbraHttpClient;
use crate::{AuthCommand, Command, ItemCommand, SyncCommand, TokenCommand, VaultCommand};

pub async fn run(command: Command, mut config: CliConfig) -> Result<(), CliError> {
    match command {
        Command::Auth(AuthCommand::Token(TokenCommand::Set { server_url, token })) => {
            config.server_url = server_url;
            config.session_token = Some(token);
            save_config(&config)?;
            println!("token saved");
            Ok(())
        }
        Command::Vault(VaultCommand::List) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config)?;
            let vaults: Vec<VaultResponse> = client.get("/api/v1/vaults").await?;
            println!("{}", serde_json::to_string_pretty(&vaults)?);
            Ok(())
        }
        Command::Vault(VaultCommand::Create {
            name,
            wrapping_json,
        }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config)?;
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
            println!("{}", serde_json::to_string_pretty(&vault)?);
            Ok(())
        }
        Command::Item(ItemCommand::Create {
            vault_id,
            kind,
            envelope_json,
        }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config)?;
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
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
        Command::Item(ItemCommand::Update {
            vault_id,
            item_id,
            expected_revision,
            envelope_json,
        }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config)?;
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
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
        Command::Sync(SyncCommand::Run {
            vault_id,
            since_vault_revision,
        }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config)?;
            let response: SyncResponse = client
                .post(
                    "/api/v1/sync",
                    &SyncRequest {
                        protocol_version: PROTOCOL_VERSION,
                        device_id: Uuid::new_v4(),
                        vaults: vec![VaultSyncCursor {
                            vault_id,
                            since_vault_revision,
                        }],
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
    }
}

fn require_token(config: &CliConfig) -> Result<(), CliError> {
    if config.session_token.is_some() {
        Ok(())
    } else {
        Err(CliError::MissingSessionToken)
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
