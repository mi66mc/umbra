use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};

use crate::error::CliError;

pub struct LocalCache {
    connection: Connection,
    profile: String,
}

impl LocalCache {
    pub fn open(profile: &str) -> Result<Self, CliError> {
        let dir = profile_cache_dir(profile);
        std::fs::create_dir_all(&dir)?;
        Self::open_path(profile, dir.join("cache.db"))
    }

    pub fn open_path(profile: &str, path: PathBuf) -> Result<Self, CliError> {
        let connection = Connection::open(path)?;
        let cache = Self {
            connection,
            profile: profile.to_owned(),
        };
        cache.create_schema()?;
        Ok(cache)
    }

    pub fn open_in_memory(profile: &str) -> Result<Self, CliError> {
        let connection = Connection::open_in_memory()?;
        let cache = Self {
            connection,
            profile: profile.to_owned(),
        };
        cache.create_schema()?;
        Ok(cache)
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn table_names(&self) -> Result<Vec<String>, CliError> {
        let mut statement = self
            .connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    fn create_schema(&self) -> Result<(), CliError> {
        self.connection.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                org_id TEXT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                latest_vault_revision INTEGER NOT NULL DEFAULT 0,
                current_key_generation INTEGER NOT NULL DEFAULT 1,
                needs_key_rotation INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                vault_id TEXT PRIMARY KEY,
                latest_vault_revision INTEGER NOT NULL DEFAULT 0,
                synced_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_key_wrappings (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                device_id TEXT,
                wrapping_type TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                key_generation INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS item_revisions (
                vault_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                vault_revision INTEGER NOT NULL,
                key_generation INTEGER NOT NULL,
                author_user_id TEXT,
                envelope_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (vault_id, item_id, revision)
            );
            "#,
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('schema_version', '1')",
            params![],
        )?;
        Ok(())
    }
}

pub fn profile_cache_dir(profile: &str) -> PathBuf {
    profile_cache_dir_from_base(&local_data_dir(), profile)
}

pub fn profile_cache_dir_from_base(base: &Path, profile: &str) -> PathBuf {
    base.join("profiles").join(sanitize_profile_name(profile))
}

fn local_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("UMBRA_CACHE_DIR") {
        return PathBuf::from(path);
    }

    let base = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
    } else {
        None
    }
    .or_else(|| std::env::var("XDG_DATA_HOME").ok().map(PathBuf::from))
    .or_else(|| {
        std::env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".local").join("share"))
    })
    .unwrap_or_else(|| PathBuf::from("."));
    base.join("umbra")
}

fn sanitize_profile_name(profile: &str) -> String {
    profile
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_cache_dir_sanitizes_profile_names() {
        let base = std::path::PathBuf::from("/tmp/umbra-cache-test");
        let path = profile_cache_dir_from_base(&base, "miguel@example.com/local");

        assert_eq!(path, base.join("profiles").join("miguel_example.com_local"));
    }

    #[test]
    fn opens_cache_and_creates_schema() {
        let cache = LocalCache::open_in_memory("personal").unwrap();

        let tables = cache.table_names().unwrap();

        assert!(tables.contains(&"cache_meta".to_owned()));
        assert!(tables.contains(&"vaults".to_owned()));
        assert!(tables.contains(&"sync_state".to_owned()));
        assert!(tables.contains(&"vault_key_wrappings".to_owned()));
        assert!(tables.contains(&"item_revisions".to_owned()));
    }
}
