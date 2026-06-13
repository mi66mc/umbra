mod commands;
mod config;
mod error;
mod http;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};
use umbra_core::{ItemId, ItemKind, RevisionId, VaultId, VaultKind};

use crate::commands::{parse_item_kind, parse_vault_kind};
use crate::config::load_config;
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
    #[command(subcommand)]
    Auth(AuthCommand),
    #[command(subcommand)]
    Vault(VaultCommand),
    #[command(subcommand)]
    Item(ItemCommand),
    #[command(subcommand)]
    Sync(SyncCommand),
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
        name: String,
        #[arg(long, value_parser = parse_vault_kind, default_value = "personal")]
        kind: VaultKind,
        #[arg(long)]
        wrapping_json: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ItemCommand {
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
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long, default_value_t = 0)]
        since_vault_revision: RevisionId,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    let config = load_config()?;
    commands::run(cli.command, config).await
}
