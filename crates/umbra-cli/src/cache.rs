use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};

use crate::error::CliError;

pub struct LocalCache {
    connection: Connection,
    profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedItemRevision {
    pub vault_id: uuid::Uuid,
    pub item_id: uuid::Uuid,
    pub revision: i64,
    pub vault_revision: i64,
    pub key_generation: i64,
    pub author_user_id: Option<uuid::Uuid>,
    pub envelope: serde_json::Value,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedKeyWrapping {
    pub id: uuid::Uuid,
    pub vault_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub device_id: Option<uuid::Uuid>,
    pub wrapping_type: String,
    pub envelope: serde_json::Value,
    pub key_generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CacheStatus {
    pub profile: String,
    pub synced_vault_count: i64,
    pub item_revision_count: i64,
    pub key_wrapping_count: i64,
    pub sync_state_count: i64,
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

    #[cfg(test)]
    pub fn open_in_memory(profile: &str) -> Result<Self, CliError> {
        let connection = Connection::open_in_memory()?;
        let cache = Self {
            connection,
            profile: profile.to_owned(),
        };
        cache.create_schema()?;
        Ok(cache)
    }

    #[cfg(test)]
    pub fn table_names(&self) -> Result<Vec<String>, CliError> {
        let mut statement = self
            .connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn apply_sync_changes(
        &mut self,
        changes: &umbra_protocol::VaultSyncChanges,
    ) -> Result<(), CliError> {
        let now = chrono::Utc::now().to_rfc3339();
        let tx = self.connection.transaction()?;
        tx.execute(
            r#"
            INSERT INTO sync_state (vault_id, latest_vault_revision, synced_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(vault_id) DO UPDATE SET
                latest_vault_revision = excluded.latest_vault_revision,
                synced_at = excluded.synced_at
            "#,
            params![
                changes.vault_id.to_string(),
                changes.latest_vault_revision,
                now
            ],
        )?;

        for item in &changes.items {
            tx.execute(
                r#"
                INSERT INTO item_revisions (
                    vault_id, item_id, revision, vault_revision, key_generation,
                    author_user_id, envelope_json, updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(vault_id, item_id, revision) DO UPDATE SET
                    vault_revision = excluded.vault_revision,
                    key_generation = excluded.key_generation,
                    author_user_id = excluded.author_user_id,
                    envelope_json = excluded.envelope_json,
                    updated_at = excluded.updated_at
                "#,
                params![
                    item.vault_id.to_string(),
                    item.item_id.to_string(),
                    item.revision,
                    item.vault_revision,
                    item.key_generation,
                    item.author_user_id.map(|id| id.to_string()),
                    serde_json::to_string(&item.envelope)?,
                    now
                ],
            )?;
        }

        for wrapping in &changes.key_wrappings {
            tx.execute(
                r#"
                INSERT INTO vault_key_wrappings (
                    id, vault_id, user_id, device_id, wrapping_type,
                    envelope_json, key_generation, updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(id) DO UPDATE SET
                    vault_id = excluded.vault_id,
                    user_id = excluded.user_id,
                    device_id = excluded.device_id,
                    wrapping_type = excluded.wrapping_type,
                    envelope_json = excluded.envelope_json,
                    key_generation = excluded.key_generation,
                    updated_at = excluded.updated_at
                "#,
                params![
                    wrapping.id.to_string(),
                    wrapping.vault_id.to_string(),
                    wrapping.user_id.to_string(),
                    wrapping.device_id.map(|id| id.to_string()),
                    wrapping.wrapping_type.as_str(),
                    serde_json::to_string(&wrapping.envelope)?,
                    wrapping.key_generation,
                    now
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn latest_vault_revision(&self, vault_id: uuid::Uuid) -> Result<Option<i64>, CliError> {
        let mut statement = self
            .connection
            .prepare("SELECT latest_vault_revision FROM sync_state WHERE vault_id = ?1")?;
        let result = statement.query_row(params![vault_id.to_string()], |row| row.get(0));
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(CliError::from(error)),
        }
    }

    #[cfg(test)]
    pub fn list_item_revisions(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<CachedItemRevision>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id, item_id, revision, vault_revision, key_generation,
                   author_user_id, envelope_json
            FROM item_revisions
            WHERE vault_id = ?1
            ORDER BY vault_revision ASC, item_id ASC, revision ASC
            "#,
        )?;
        let rows =
            statement.query_map(params![vault_id.to_string()], cached_item_revision_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    #[cfg(test)]
    pub fn list_key_wrappings(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<CachedKeyWrapping>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT id, vault_id, user_id, device_id, wrapping_type, envelope_json, key_generation
            FROM vault_key_wrappings
            WHERE vault_id = ?1
            ORDER BY key_generation ASC, id ASC
            "#,
        )?;
        let rows =
            statement.query_map(params![vault_id.to_string()], cached_key_wrapping_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn list_latest_item_revisions(
        &self,
        vault_id: uuid::Uuid,
    ) -> Result<Vec<CachedItemRevision>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT ir.vault_id, ir.item_id, ir.revision, ir.vault_revision, ir.key_generation,
                   ir.author_user_id, ir.envelope_json
            FROM item_revisions ir
            INNER JOIN (
                SELECT vault_id, item_id, MAX(revision) AS max_revision
                FROM item_revisions
                WHERE vault_id = ?1
                GROUP BY vault_id, item_id
            ) latest
              ON latest.vault_id = ir.vault_id
             AND latest.item_id = ir.item_id
             AND latest.max_revision = ir.revision
            WHERE ir.vault_id = ?1
            ORDER BY ir.vault_revision ASC, ir.item_id ASC
            "#,
        )?;
        let rows =
            statement.query_map(params![vault_id.to_string()], cached_item_revision_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
    }

    pub fn latest_item_revision(
        &self,
        vault_id: uuid::Uuid,
        item_id: uuid::Uuid,
    ) -> Result<Option<CachedItemRevision>, CliError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT vault_id, item_id, revision, vault_revision, key_generation,
                   author_user_id, envelope_json
            FROM item_revisions
            WHERE vault_id = ?1 AND item_id = ?2
            ORDER BY revision DESC
            LIMIT 1
            "#,
        )?;
        let result = statement.query_row(
            params![vault_id.to_string(), item_id.to_string()],
            cached_item_revision_from_row,
        );
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(CliError::from(error)),
        }
    }

    pub fn status(&self) -> Result<CacheStatus, CliError> {
        Ok(CacheStatus {
            profile: self.profile.clone(),
            synced_vault_count: self.count_table("sync_state")?,
            item_revision_count: self.count_table("item_revisions")?,
            key_wrapping_count: self.count_table("vault_key_wrappings")?,
            sync_state_count: self.count_table("sync_state")?,
        })
    }

    fn count_table(&self, table: &str) -> Result<i64, CliError> {
        let sql = match table {
            "item_revisions" => "SELECT COUNT(*) FROM item_revisions",
            "vault_key_wrappings" => "SELECT COUNT(*) FROM vault_key_wrappings",
            "sync_state" => "SELECT COUNT(*) FROM sync_state",
            _ => return Err(CliError::Input("unknown cache table")),
        };
        Ok(self.connection.query_row(sql, [], |row| row.get(0))?)
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

fn cached_item_revision_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<CachedItemRevision, rusqlite::Error> {
    let author_user_id: Option<String> = row.get(5)?;
    let envelope_json: String = row.get(6)?;
    Ok(CachedItemRevision {
        vault_id: parse_uuid(row.get::<_, String>(0)?)?,
        item_id: parse_uuid(row.get::<_, String>(1)?)?,
        revision: row.get(2)?,
        vault_revision: row.get(3)?,
        key_generation: row.get(4)?,
        author_user_id: author_user_id.map(parse_uuid).transpose()?,
        envelope: parse_json(envelope_json)?,
    })
}

#[cfg(test)]
fn cached_key_wrapping_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<CachedKeyWrapping, rusqlite::Error> {
    let device_id: Option<String> = row.get(3)?;
    let envelope_json: String = row.get(5)?;
    Ok(CachedKeyWrapping {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        vault_id: parse_uuid(row.get::<_, String>(1)?)?,
        user_id: parse_uuid(row.get::<_, String>(2)?)?,
        device_id: device_id.map(parse_uuid).transpose()?,
        wrapping_type: row.get(4)?,
        envelope: parse_json(envelope_json)?,
        key_generation: row.get(6)?,
    })
}

fn parse_uuid(value: String) -> Result<uuid::Uuid, rusqlite::Error> {
    uuid::Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_json(value: String) -> Result<serde_json::Value, rusqlite::Error> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
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

    #[test]
    fn upserts_sync_changes_and_tracks_cursor() {
        let mut cache = LocalCache::open_in_memory("personal").unwrap();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let item_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let wrapping_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let user_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let changes = umbra_protocol::VaultSyncChanges {
            vault_id,
            latest_vault_revision: 7,
            items: vec![umbra_protocol::ItemRevisionResponse {
                item_id,
                vault_id,
                revision: 2,
                vault_revision: 7,
                key_generation: 1,
                author_user_id: Some(user_id),
                envelope: serde_json::json!({"ciphertext": "encrypted"}),
            }],
            deleted_items: vec![],
            key_wrappings: vec![umbra_protocol::VaultKeyWrappingResponse {
                id: wrapping_id,
                vault_id,
                user_id,
                device_id: None,
                wrapping_type: "user_public_key".to_owned(),
                envelope: serde_json::json!({"wrapped": true}),
                key_generation: 1,
            }],
        };

        cache.apply_sync_changes(&changes).unwrap();

        assert_eq!(cache.latest_vault_revision(vault_id).unwrap(), Some(7));
        assert_eq!(cache.list_item_revisions(vault_id).unwrap().len(), 1);
        assert_eq!(cache.list_key_wrappings(vault_id).unwrap().len(), 1);
    }
}
