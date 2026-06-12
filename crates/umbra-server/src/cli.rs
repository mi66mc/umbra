use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "umbra-server")]
#[command(about = "Umbra HTTP server and administration commands")]
pub(crate) struct Cli {
    #[arg(long, global = true)]
    pub(crate) config: Option<String>,
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Serve,
    Migrate {
        #[command(subcommand)]
        command: Option<MigrateCommand>,
    },
    Doctor,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Opaque {
        #[command(subcommand)]
        command: OpaqueCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum MigrateCommand {
    Status,
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommand {
    Print,
}

#[derive(Subcommand)]
pub(crate) enum OpaqueCommand {
    Setup {
        #[command(subcommand)]
        command: OpaqueSetupCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum OpaqueSetupCommand {
    Generate,
}
