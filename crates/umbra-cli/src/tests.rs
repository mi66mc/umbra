use clap::Parser;

use crate::config::CliConfig;
use crate::{Cli, Command};

#[test]
fn parses_token_set_command() {
    let cli = Cli::parse_from([
        "umbra",
        "auth",
        "token",
        "set",
        "--server-url",
        "http://localhost:8080",
        "--token",
        "abc",
    ]);

    match cli.command {
        Command::Auth(auth) => {
            assert!(format!("{auth:?}").contains("Token"));
        }
        _ => panic!("expected auth command"),
    }
}

#[test]
fn config_roundtrips_toml() {
    let config = CliConfig {
        server_url: "http://localhost:8080".to_owned(),
        session_token: Some("abc".to_owned()),
    };

    let encoded = toml::to_string(&config).unwrap();
    let decoded: CliConfig = toml::from_str(&encoded).unwrap();

    assert_eq!(decoded.server_url, "http://localhost:8080");
    assert_eq!(decoded.session_token.as_deref(), Some("abc"));
}
