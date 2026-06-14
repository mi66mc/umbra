use clap::Parser;

use crate::config::{CliConfig, ProfileConfig};
use crate::{AuthCommand, Cli, Command, ProfileCommand, TokenCommand, VaultCommand};

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
    let mut config = CliConfig::default();
    let profile = ProfileConfig {
        server_url: "http://localhost:8080".to_owned(),
        legacy_session_token: Some("abc".to_owned()),
        ..ProfileConfig::default()
    };
    config.profiles.insert("personal".to_owned(), profile);
    config.active_profile = "personal".to_owned();

    let encoded = toml::to_string(&config).unwrap();
    let decoded: CliConfig = toml::from_str(&encoded).unwrap();

    let profile = decoded.profiles.get("personal").unwrap();
    assert_eq!(profile.server_url, "http://localhost:8080");
    assert_eq!(profile.legacy_session_token.as_deref(), Some("abc"));
}

#[test]
fn parses_profile_commands() {
    let list = Cli::parse_from(["umbra", "profile", "list"]);
    assert!(matches!(
        list.command,
        Command::Profile(ProfileCommand::List)
    ));

    let use_profile = Cli::parse_from(["umbra", "profile", "use", "personal"]);
    assert!(matches!(
        use_profile.command,
        Command::Profile(ProfileCommand::Use { .. })
    ));
}

#[test]
fn signed_profile_roundtrips() {
    let profile = ProfileConfig {
        session_id: Some(uuid::Uuid::new_v4()),
        device_id: Some(uuid::Uuid::new_v4()),
        device_private_key: Some("private".to_owned()),
        ..ProfileConfig::default()
    };

    let encoded = toml::to_string(&profile).unwrap();
    let decoded: ProfileConfig = toml::from_str(&encoded).unwrap();

    assert_eq!(decoded.session_id, profile.session_id);
    assert_eq!(decoded.device_private_key.as_deref(), Some("private"));
}
