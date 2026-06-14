mod cache;
mod commands;
mod config;
mod crypto_state;
mod error;
mod http;
mod keys;
mod opaque;
mod output;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use sha2::Sha512;
use umbra_core::{ItemId, ItemKind, RevisionId, VaultId};

use crate::commands::parse_item_kind;
use crate::config::{CliConfig, load_config};
use crate::error::CliError;

#[derive(Debug, Parser)]
#[command(name = "umbra")]
#[command(about = "Umbra command line client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Register {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        device_name: Option<String>,
    },
    Login {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        email: Option<String>,
    },
    #[command(subcommand)]
    Auth(AuthCommand),
    #[command(subcommand)]
    Cache(CacheCommand),
    #[command(subcommand)]
    Profile(ProfileCommand),
    #[command(subcommand)]
    Vault(VaultCommand),
    #[command(subcommand)]
    Item(ItemCommand),
    #[command(subcommand, alias = "s")]
    Sync(SyncCommand),
}

pub(crate) struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    List,
    Use { name: String },
}

#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    Status,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    Set {
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        token: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    List,
    Create {
        name: Option<String>,
        #[arg(long)]
        wrapping_json: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ItemCommand {
    List {
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long)]
        cached: bool,
    },
    Get {
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long)]
        item_id: ItemId,
        #[arg(long)]
        cached: bool,
    },
    Create {
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long, value_parser = parse_item_kind)]
        kind: ItemKind,
        #[arg(long)]
        envelope_json: String,
    },
    Update {
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long)]
        item_id: ItemId,
        #[arg(long)]
        expected_revision: RevisionId,
        #[arg(long)]
        envelope_json: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    Run {
        #[arg(long = "vault", alias = "vault-id")]
        vault_id: VaultId,
        #[arg(long)]
        since_vault_revision: Option<RevisionId>,
        #[arg(long)]
        force_full: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    let config = load_config_for_command(&cli.command)?;
    commands::run(cli.command, config).await
}

fn load_config_for_command(command: &Command) -> Result<CliConfig, CliError> {
    match load_config() {
        Ok(config) => Ok(config),
        Err(CliError::TomlDecode(_))
            if matches!(
                command,
                Command::Register { .. }
                    | Command::Login { .. }
                    | Command::Auth(AuthCommand::Token(TokenCommand::Set { .. }))
            ) =>
        {
            Ok(CliConfig::default())
        }
        Err(error) => Err(error),
    }
}
