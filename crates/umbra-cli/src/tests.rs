use clap::Parser;

use crate::config::CliConfig;
use crate::{AuthCommand, Cli, Command, TokenCommand, VaultCommand};

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

    let Command::Auth(AuthCommand::Token(TokenCommand::Set { server_url, token })) = cli.command
    else {
        panic!("expected auth token set command");
    };

    assert_eq!(server_url, "http://localhost:8080");
    assert_eq!(token, "abc");
}

#[test]
fn parses_vault_create_as_personal_without_kind() {
    let cli = Cli::parse_from([
        "umbra",
        "vault",
        "create",
        "personal",
        "--wrapping-json",
        r#"{"alg":"test"}"#,
    ]);

    let Command::Vault(VaultCommand::Create {
        name,
        wrapping_json,
    }) = cli.command
    else {
        panic!("expected vault create command");
    };

    assert_eq!(name, "personal");
    assert_eq!(wrapping_json, r#"{"alg":"test"}"#);
}

#[test]
fn rejects_vault_create_kind_option() {
    let result = Cli::try_parse_from([
        "umbra",
        "vault",
        "create",
        "shared",
        "--kind",
        "shared",
        "--wrapping-json",
        r#"{"alg":"test"}"#,
    ]);

    assert!(result.is_err());
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
