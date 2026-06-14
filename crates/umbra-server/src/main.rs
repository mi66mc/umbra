mod authz;
mod cli;
mod config;
mod error;
mod http;
mod server;
mod signed_auth;
mod state;
mod util;

#[cfg(test)]
mod tests;

use clap::Parser;

use cli::{Cli, Command, ConfigCommand, MigrateCommand, OpaqueCommand, OpaqueSetupCommand};
use config::load_config;
use error::ServerError;
use server::{doctor, migrate, migrate_status, serve};
use util::generate_opaque_server_setup_secret;

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = load_config(cli.config.as_deref())?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config).await,
        Command::Migrate { command: None } => migrate(config).await,
        Command::Migrate {
            command: Some(MigrateCommand::Status),
        } => migrate_status(config).await,
        Command::Doctor => doctor(config).await,
        Command::Config {
            command: ConfigCommand::Print,
        } => {
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
        Command::Opaque {
            command:
                OpaqueCommand::Setup {
                    command: OpaqueSetupCommand::Generate,
                },
        } => {
            println!("{}", generate_opaque_server_setup_secret());
            Ok(())
        }
    }
}
