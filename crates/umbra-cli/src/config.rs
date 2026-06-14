use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::error::CliError;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliConfig {
    #[serde(default = "default_profile_name")]
    pub active_profile: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(default = "default_server_url")]
    pub server_url: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub device_id: Option<Uuid>,
    #[serde(default)]
    pub session_id: Option<Uuid>,
    #[serde(default)]
    pub device_private_key: Option<String>,
    #[serde(default)]
    pub client_public_key: Option<String>,
    #[serde(default)]
    pub encrypted_user_private_key: Option<serde_json::Value>,
    #[serde(default)]
    pub kdf_params: Option<umbra_crypto::Argon2idParams>,
    #[serde(default)]
    pub user_secret_key: Option<String>,
    #[serde(default)]
    pub legacy_session_token: Option<String>,
}

impl fmt::Debug for CliConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliConfig")
            .field("active_profile", &self.active_profile)
            .field("profiles", &self.profiles)
            .field("server_url", &self.server_url)
            .field("session_token", &self.session_token)
            .finish()
    }
}

impl fmt::Debug for ProfileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let user_secret_key = self.user_secret_key.as_ref().map(|_| "[redacted]");

        f.debug_struct("ProfileConfig")
            .field("server_url", &self.server_url)
            .field("email", &self.email)
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("session_id", &self.session_id)
            .field("device_private_key", &self.device_private_key)
            .field("client_public_key", &self.client_public_key)
            .field(
                "encrypted_user_private_key",
                &self.encrypted_user_private_key,
            )
            .field("kdf_params", &self.kdf_params)
            .field("user_secret_key", &user_secret_key)
            .field("legacy_session_token", &self.legacy_session_token)
            .finish()
    }
}

impl Default for CliConfig {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(default_profile_name(), ProfileConfig::default());
        Self {
            active_profile: default_profile_name(),
            profiles,
            server_url: None,
            session_token: None,
        }
    }
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
            email: None,
            user_id: None,
            device_id: None,
            session_id: None,
            device_private_key: None,
            client_public_key: None,
            encrypted_user_private_key: None,
            kdf_params: None,
            user_secret_key: None,
            legacy_session_token: None,
        }
    }
}

fn default_profile_name() -> String {
    "default".to_owned()
}

fn default_server_url() -> String {
    "http://127.0.0.1:8080".to_owned()
}

pub fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("UMBRA_CONFIG") {
        return PathBuf::from(path);
    }

    let base = if cfg!(windows) {
        std::env::var("APPDATA").ok().map(PathBuf::from)
    } else {
        None
    }
    .or_else(|| std::env::var("XDG_CONFIG_HOME").ok().map(PathBuf::from))
    .or_else(|| {
        std::env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".config"))
    })
    .unwrap_or_else(|| PathBuf::from("."));
    base.join("umbra").join("config.toml")
}

pub fn load_config() -> Result<CliConfig, CliError> {
    let path = config_path();
    if !path.exists() {
        return Ok(CliConfig::default());
    }

    let contents = std::fs::read_to_string(path)?;
    let mut config: CliConfig = toml::from_str(&contents)?;
    migrate_legacy_config(&mut config);
    Ok(config)
}

pub fn save_config(config: &CliConfig) -> Result<(), CliError> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, toml::to_string_pretty(config)?)?;
    Ok(())
}

pub fn active_profile(config: &CliConfig) -> Result<&ProfileConfig, CliError> {
    config
        .profiles
        .get(&config.active_profile)
        .ok_or_else(|| CliError::MissingProfile(config.active_profile.clone()))
}

pub fn active_profile_mut(config: &mut CliConfig) -> &mut ProfileConfig {
    config
        .profiles
        .entry(config.active_profile.clone())
        .or_default()
}

pub fn set_active_profile(config: &mut CliConfig, name: String) {
    config.active_profile = name.clone();
    config.profiles.entry(name).or_default();
}

fn migrate_legacy_config(config: &mut CliConfig) {
    if config.profiles.is_empty() {
        config.profiles.insert(
            config.active_profile.clone(),
            ProfileConfig {
                server_url: config.server_url.clone().unwrap_or_else(default_server_url),
                legacy_session_token: config.session_token.clone(),
                ..ProfileConfig::default()
            },
        );
    }
    config.server_url = None;
    config.session_token = None;
}
