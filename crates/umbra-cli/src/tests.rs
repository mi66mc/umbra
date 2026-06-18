use clap::Parser;

use crate::config::{CliConfig, ProfileConfig};
use crate::{
    AuthCommand, CacheCommand, Cli, Command, ItemCommand, ProfileCommand, SecretCommand,
    TokenCommand, VaultCommand,
};

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

    assert_eq!(name.as_deref(), Some("personal"));
    assert_eq!(wrapping_json.as_deref(), Some(r#"{"alg":"test"}"#));
}

#[test]
fn parses_vault_create_without_wrapping_json() {
    let cli = Cli::parse_from(["umbra", "vault", "create", "personal"]);

    let Command::Vault(VaultCommand::Create {
        name,
        wrapping_json,
    }) = cli.command
    else {
        panic!("expected vault create command");
    };

    assert_eq!(name.as_deref(), Some("personal"));
    assert_eq!(wrapping_json, None);
}

#[test]
fn parses_register_and_login_commands() {
    let register = Cli::parse_from([
        "umbra",
        "register",
        "--server",
        "http://127.0.0.1:8080",
        "--email",
        "miguel@example.com",
        "--profile",
        "personal",
    ]);
    assert!(matches!(register.command, Command::Register { .. }));

    let login = Cli::parse_from(["umbra", "login", "--profile", "personal"]);
    assert!(matches!(login.command, Command::Login { .. }));
}

#[test]
fn parses_sugar_commands() {
    let vault = Cli::parse_from(["umbra", "vault", "create"]);
    assert!(matches!(
        vault.command,
        Command::Vault(VaultCommand::Create { name: None, .. })
    ));

    let sync = Cli::parse_from([
        "umbra",
        "sync",
        "run",
        "--vault",
        "00000000-0000-0000-0000-000000000001",
    ]);
    assert!(matches!(sync.command, Command::Sync(_)));
}

#[test]
fn parses_sync_force_full() {
    let sync = Cli::parse_from([
        "umbra",
        "sync",
        "run",
        "--vault",
        "00000000-0000-0000-0000-000000000001",
        "--force-full",
    ]);

    assert!(matches!(
        sync.command,
        Command::Sync(crate::SyncCommand::Run {
            force_full: true,
            ..
        })
    ));
}

#[test]
fn parses_cached_item_commands() {
    let list = Cli::parse_from([
        "umbra",
        "item",
        "list",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
        "--cached",
    ]);
    assert!(matches!(
        list.command,
        Command::Item(crate::ItemCommand::List { offline: true, .. })
    ));

    let get = Cli::parse_from([
        "umbra",
        "item",
        "get",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
        "--item-id",
        "00000000-0000-0000-0000-000000000002",
        "--cached",
    ]);
    assert!(matches!(
        get.command,
        Command::Item(crate::ItemCommand::Get { offline: true, .. })
    ));
}

#[test]
fn parses_offline_read_commands() {
    let list = Cli::parse_from([
        "umbra",
        "item",
        "list",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
        "--offline",
    ]);
    assert!(matches!(
        list.command,
        Command::Item(crate::ItemCommand::List { offline: true, .. })
    ));

    let secret = Cli::parse_from([
        "umbra",
        "secret",
        "get",
        "umbra/prod",
        "OPENAI_API_KEY",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
        "--offline",
    ]);
    assert!(matches!(
        secret.command,
        Command::Secret(SecretCommand::Get { offline: true, .. })
    ));
}

#[test]
fn parses_item_create_plaintext() {
    let cli = Cli::parse_from([
        "umbra",
        "item",
        "create",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
        "--kind",
        "login",
        "--title",
        "Example",
        "--field",
        "username=miguel",
        "--field",
        "password=secret",
        "--notes",
        "private note",
        "--tag",
        "work",
        "--tag",
        "prod",
    ]);

    let Command::Item(ItemCommand::Create {
        kind,
        title,
        fields,
        notes,
        tags,
        envelope_json,
        ..
    }) = cli.command
    else {
        panic!("expected item create command");
    };

    assert_eq!(kind, umbra_core::ItemKind::Login);
    assert_eq!(title.as_deref(), Some("Example"));
    assert_eq!(
        fields,
        vec!["username=miguel".to_owned(), "password=secret".to_owned()]
    );
    assert_eq!(notes.as_deref(), Some("private note"));
    assert_eq!(tags, vec!["work".to_owned(), "prod".to_owned()]);
    assert_eq!(envelope_json, None);
}

#[test]
fn parses_secret_commands() {
    let set = Cli::parse_from([
        "umbra",
        "secret",
        "set",
        "umbra/prod",
        "OPENAI_API_KEY",
        "secret-value",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
    ]);
    assert!(matches!(
        set.command,
        Command::Secret(SecretCommand::Set {
            project_env,
            key,
            value: Some(_),
            ..
        }) if project_env == "umbra/prod" && key == "OPENAI_API_KEY"
    ));

    let get = Cli::parse_from([
        "umbra",
        "secret",
        "get",
        "umbra/prod",
        "OPENAI_API_KEY",
        "--vault-id",
        "00000000-0000-0000-0000-000000000001",
    ]);
    assert!(matches!(
        get.command,
        Command::Secret(SecretCommand::Get {
            project_env,
            key,
            ..
        }) if project_env == "umbra/prod" && key == "OPENAI_API_KEY"
    ));
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
        client_public_key: Some("client-public-key".to_owned()),
        encrypted_user_private_key: Some(serde_json::json!({
            "version": 1,
            "suite": "UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1",
            "nonce": "nonce",
            "aad": "aad",
            "ciphertext": "ciphertext"
        })),
        kdf_params: Some(umbra_crypto::Argon2idParams::balanced_with_salt(
            umbra_crypto::Salt::from_bytes([1u8; 16]).to_base64url(),
        )),
        user_secret_key: Some("secret-key".to_owned()),
        ..ProfileConfig::default()
    };
    config.profiles.insert("personal".to_owned(), profile);
    config.active_profile = "personal".to_owned();

    let encoded = toml::to_string(&config).unwrap();
    let decoded: CliConfig = toml::from_str(&encoded).unwrap();

    let profile = decoded.profiles.get("personal").unwrap();
    assert_eq!(profile.server_url, "http://localhost:8080");
    assert_eq!(profile.legacy_session_token.as_deref(), Some("abc"));
    assert_eq!(
        profile.client_public_key.as_deref(),
        Some("client-public-key")
    );
    assert_eq!(
        profile
            .encrypted_user_private_key
            .as_ref()
            .and_then(|value| value.get("ciphertext"))
            .and_then(serde_json::Value::as_str),
        Some("ciphertext")
    );
    let kdf_params = profile.kdf_params.as_ref().unwrap();
    assert_eq!(kdf_params.profile, umbra_crypto::KdfProfile::Balanced);
    assert_eq!(profile.user_secret_key.as_deref(), Some("secret-key"));
}

#[test]
fn debug_redacts_user_secret_key() {
    let profile = ProfileConfig {
        user_secret_key: Some("super-secret-key".to_owned()),
        ..ProfileConfig::default()
    };
    let debug = format!("{profile:?}");

    assert!(!debug.contains("super-secret-key"));
    assert!(debug.contains("[redacted]"));

    let mut config = CliConfig::default();
    config.profiles.insert("personal".to_owned(), profile);
    let debug = format!("{config:?}");

    assert!(!debug.contains("super-secret-key"));
    assert!(debug.contains("[redacted]"));
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
fn parses_cache_status_command() {
    let cli = Cli::parse_from(["umbra", "cache", "status"]);

    assert!(matches!(cli.command, Command::Cache(CacheCommand::Status)));
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
