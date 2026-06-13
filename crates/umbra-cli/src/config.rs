use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::CliError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    pub session_token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".to_owned(),
            session_token: None,
        }
    }
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
    Ok(toml::from_str(&contents)?)
}

pub fn save_config(config: &CliConfig) -> Result<(), CliError> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, toml::to_string_pretty(config)?)?;
    Ok(())
}
