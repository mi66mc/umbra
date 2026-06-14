# CLI SQLite Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a local SQLite cache for the Umbra CLI so `sync` persists encrypted vault/item envelopes and later commands can read local state without losing the zero-knowledge boundary.

**Architecture:** Implement cache as a CLI-only module backed by `rusqlite`, stored per local profile under Umbra's local data directory. The cache stores encrypted envelopes, key wrappings, sync cursors, and non-secret metadata; it must not store plaintext secrets or vault keys. Existing server sync remains the source of truth and the first version only caches remote state after explicit `umbra sync run`.

**Tech Stack:** Rust 1.88, `rusqlite` with bundled SQLite, existing `umbra-cli`, `umbra-protocol`, UUIDs, JSON envelopes, Clap, current signed HTTP client.

---

## Scope

This implementation is primarily a CLI feature.

Server changes are intentionally not required in this plan because the current server already returns:

```txt
SyncResponse
  vault_id
  latest_vault_revision
  items[]
  key_wrappings[]
```

The current protocol is enough to cache encrypted item revisions and key wrappings.

This plan does not implement:

- plaintext item decrypt/read UX;
- local unlock daemon;
- encrypted SQLite database;
- SQLCipher;
- offline write queue;
- conflict resolution;
- automatic background sync.

The cache is still valuable immediately because it gives Umbra:

- durable sync cursors;
- local encrypted envelope storage;
- local key wrapping storage;
- `umbra cache status`;
- `umbra item list --cached`;
- `umbra item get --cached --item-id <id>` returning encrypted envelope JSON;
- fewer repeated full syncs.

## Security Rules

The cache may store:

```txt
profile name
server url
user_id
device_id
vault_id
org_id
vault name
vault kind
revision numbers
item_id
item kind when known locally
encrypted item envelope JSON
encrypted vault key wrapping JSON
timestamps
```

The cache must not store:

```txt
master password
secret key
account KEK
vault key plaintext
item plaintext
password plaintext
API key plaintext
SSH private key plaintext
decrypted note text
```

This is not yet a fully encrypted cache. It is a structured local database of already-encrypted envelopes plus metadata.

## File Structure

Create:

- `crates/umbra-cli/src/cache.rs`: local SQLite path resolution, schema creation, repository methods, cache structs.

Modify:

- `crates/umbra-cli/Cargo.toml`: add `rusqlite`.
- `crates/umbra-cli/src/main.rs`: add `mod cache;`, `CacheCommand`, `--cached` flags, and `item get/list` parser shapes.
- `crates/umbra-cli/src/commands.rs`: write sync responses into cache, add cache commands, add cached item commands.
- `crates/umbra-cli/src/error.rs`: add cache-related error variants.
- `crates/umbra-cli/src/tests.rs`: add parser and cache unit tests.
- `README.md`: document local cache behavior and commands.
- `docs/protocol.md`: document that sync responses are cacheable encrypted envelopes.
- `docs/threat-model.md`: document local cache limitations.

Do not modify server code in this plan unless a test proves the CLI cannot cache required sync data.

---

### Task 1: Add Local Cache Module Skeleton

**Files:**
- Modify: `crates/umbra-cli/Cargo.toml`
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/error.rs`
- Create: `crates/umbra-cli/src/cache.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add failing cache path and schema tests**

Create `crates/umbra-cli/src/cache.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_cache_dir_sanitizes_profile_names() {
        let base = std::path::PathBuf::from("/tmp/umbra-cache-test");
        let path = profile_cache_dir_from_base(&base, "miguel@example.com/local");

        assert_eq!(
            path,
            base.join("profiles").join("miguel_example.com_local")
        );
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
```

- [ ] **Step 2: Add dependencies and module declaration**

In `crates/umbra-cli/Cargo.toml`, add:

```toml
rusqlite = { version = "0.32", features = ["bundled"] }
```

In `crates/umbra-cli/src/main.rs`, add:

```rust
mod cache;
```

In `crates/umbra-cli/src/error.rs`, add:

```rust
#[error("cache error: {0}")]
Cache(#[from] rusqlite::Error),
```

- [ ] **Step 3: Run test and verify failure**

Run:

```bash
cargo test -p umbra-cli cache::tests::profile_cache_dir_sanitizes_profile_names cache::tests::opens_cache_and_creates_schema
```

Expected: compile fails because `LocalCache`, `profile_cache_dir_from_base`, and `table_names` do not exist.

- [ ] **Step 4: Implement cache schema**

Replace `crates/umbra-cli/src/cache.rs` with:

```rust
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
        let mut statement = self.connection.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC",
        )?;
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

        assert_eq!(
            path,
            base.join("profiles").join("miguel_example.com_local")
        );
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
```

- [ ] **Step 5: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli cache::tests
cargo fmt --all
```

Expected: tests pass.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/umbra-cli
git commit -m "feat(cli): add sqlite cache schema"
```

---

### Task 2: Persist Sync Responses Into Cache

**Files:**
- Modify: `crates/umbra-cli/src/cache.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add failing cache upsert test**

Append to `crates/umbra-cli/src/cache.rs` tests:

```rust
#[test]
fn upserts_sync_changes_and_tracks_cursor() {
    let cache = LocalCache::open_in_memory("personal").unwrap();
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
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p umbra-cli upserts_sync_changes_and_tracks_cursor
```

Expected: compile fails because `apply_sync_changes`, `latest_vault_revision`, `list_item_revisions`, and `list_key_wrappings` do not exist.

- [ ] **Step 3: Add cached record structs**

In `crates/umbra-cli/src/cache.rs`, below `LocalCache`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedItemRevision {
    pub vault_id: uuid::Uuid,
    pub item_id: uuid::Uuid,
    pub revision: i64,
    pub vault_revision: i64,
    pub key_generation: i64,
    pub author_user_id: Option<uuid::Uuid>,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedKeyWrapping {
    pub id: uuid::Uuid,
    pub vault_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub device_id: Option<uuid::Uuid>,
    pub wrapping_type: String,
    pub envelope: serde_json::Value,
    pub key_generation: i64,
}
```

- [ ] **Step 4: Implement sync cache writes and reads**

In `impl LocalCache`, add:

```rust
pub fn apply_sync_changes(
    &self,
    changes: &umbra_protocol::VaultSyncChanges,
) -> Result<(), CliError> {
    let now = chrono::Utc::now().to_rfc3339();
    let tx = self.connection.unchecked_transaction()?;
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
                wrapping.wrapping_type,
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
    let mut statement = self.connection.prepare(
        "SELECT latest_vault_revision FROM sync_state WHERE vault_id = ?1",
    )?;
    let result = statement.query_row(params![vault_id.to_string()], |row| row.get(0));
    match result {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(CliError::from(error)),
    }
}

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
    let rows = statement.query_map(params![vault_id.to_string()], cached_item_revision_from_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
}

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
    let rows = statement.query_map(params![vault_id.to_string()], cached_key_wrapping_from_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
}
```

Below `sanitize_profile_name`, add:

```rust
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
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_json(value: String) -> Result<serde_json::Value, rusqlite::Error> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}
```

- [ ] **Step 5: Update `sync run` to persist cache**

In `crates/umbra-cli/src/commands.rs`, inside `Command::Sync(SyncCommand::Run { ... })`, after receiving `response`, insert:

```rust
let cache = crate::cache::LocalCache::open(&config.active_profile)?;
for vault in &response.vaults {
    cache.apply_sync_changes(vault)?;
}
```

The full ending of the branch should be:

```rust
let response: SyncResponse = client
    .post(
        "/api/v1/sync",
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id,
            vaults: vec![VaultSyncCursor {
                vault_id,
                since_vault_revision,
            }],
        },
    )
    .await?;
let cache = crate::cache::LocalCache::open(&config.active_profile)?;
for vault in &response.vaults {
    cache.apply_sync_changes(vault)?;
}
print_json(&response)
```

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli cache::tests
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli
git commit -m "feat(cli): persist sync responses in cache"
```

---

### Task 3: Add Cache Status Command

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/cache.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add failing parser test**

Append to `crates/umbra-cli/src/tests.rs`:

```rust
#[test]
fn parses_cache_status_command() {
    let cli = Cli::parse_from(["umbra", "cache", "status"]);

    assert!(matches!(cli.command, Command::Cache(CacheCommand::Status)));
}
```

Update imports at the top:

```rust
use crate::{AuthCommand, CacheCommand, Cli, Command, ProfileCommand, TokenCommand, VaultCommand};
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p umbra-cli parses_cache_status_command
```

Expected: compile fails because `CacheCommand` and `Command::Cache` do not exist.

- [ ] **Step 3: Add command shape**

In `crates/umbra-cli/src/main.rs`, add to `Command`:

```rust
#[command(subcommand)]
Cache(CacheCommand),
```

Below `ProfileCommand`, add:

```rust
#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    Status,
}
```

- [ ] **Step 4: Add cache summary methods**

In `crates/umbra-cli/src/cache.rs`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CacheStatus {
    pub profile: String,
    pub vault_count: i64,
    pub item_revision_count: i64,
    pub key_wrapping_count: i64,
    pub sync_state_count: i64,
}
```

In `impl LocalCache`, add:

```rust
pub fn status(&self) -> Result<CacheStatus, CliError> {
    Ok(CacheStatus {
        profile: self.profile.clone(),
        vault_count: self.count_table("vaults")?,
        item_revision_count: self.count_table("item_revisions")?,
        key_wrapping_count: self.count_table("vault_key_wrappings")?,
        sync_state_count: self.count_table("sync_state")?,
    })
}

fn count_table(&self, table: &str) -> Result<i64, CliError> {
    let sql = match table {
        "vaults" => "SELECT COUNT(*) FROM vaults",
        "item_revisions" => "SELECT COUNT(*) FROM item_revisions",
        "vault_key_wrappings" => "SELECT COUNT(*) FROM vault_key_wrappings",
        "sync_state" => "SELECT COUNT(*) FROM sync_state",
        _ => return Err(CliError::Input("unknown cache table")),
    };
    Ok(self.connection.query_row(sql, [], |row| row.get(0))?)
}
```

- [ ] **Step 5: Handle cache status command**

In `crates/umbra-cli/src/commands.rs`, update imports:

```rust
use crate::{
    AuthCommand, CacheCommand, Command, ItemCommand, ProfileCommand, SyncCommand, TokenCommand,
    VaultCommand,
};
```

Add a branch to `run`:

```rust
Command::Cache(CacheCommand::Status) => {
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    print_json(&cache.status()?)
}
```

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli parses_cache_status_command
cargo test -p umbra-cli cache::tests
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli
git commit -m "feat(cli): add cache status command"
```

---

### Task 4: Add Cached Item List And Get Commands

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/cache.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add failing parser tests**

Append to `crates/umbra-cli/src/tests.rs`:

```rust
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
        Command::Item(crate::ItemCommand::List { cached: true, .. })
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
        Command::Item(crate::ItemCommand::Get { cached: true, .. })
    ));
}
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p umbra-cli parses_cached_item_commands
```

Expected: compile fails because `ItemCommand::List` and `ItemCommand::Get` do not exist.

- [ ] **Step 3: Add parser shapes**

In `crates/umbra-cli/src/main.rs`, add to `ItemCommand` before `Create`:

```rust
List {
    #[arg(long)]
    vault_id: VaultId,
    #[arg(long)]
    cached: bool,
},
Get {
    #[arg(long)]
    vault_id: VaultId,
    #[arg(long)]
    item_id: ItemId,
    #[arg(long)]
    cached: bool,
},
```

- [ ] **Step 4: Add latest item revision lookup**

In `crates/umbra-cli/src/cache.rs`, add:

```rust
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
```

- [ ] **Step 5: Add command handlers**

In `crates/umbra-cli/src/commands.rs`, add branches before `ItemCommand::Create`:

```rust
Command::Item(ItemCommand::List { vault_id, cached }) => {
    if !cached {
        return Err(CliError::Input("remote item list is not implemented yet; use --cached after sync"));
    }
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    print_json(&cache.list_item_revisions(vault_id)?)
}
Command::Item(ItemCommand::Get {
    vault_id,
    item_id,
    cached,
}) => {
    if !cached {
        return Err(CliError::Input("remote item get is not implemented yet; use --cached after sync"));
    }
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let Some(revision) = cache.latest_item_revision(vault_id, item_id)? else {
        return Err(CliError::Input("cached item not found"));
    };
    print_json(&revision)
}
```

- [ ] **Step 6: Ensure cached structs serialize**

In `crates/umbra-cli/src/cache.rs`, update derives:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedItemRevision { ... }

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedKeyWrapping { ... }
```

- [ ] **Step 7: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli parses_cached_item_commands
cargo test -p umbra-cli cache::tests
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli
git commit -m "feat(cli): add cached item commands"
```

---

### Task 5: Use Cached Cursor For Sync By Default

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add parser test for forcing full sync**

Append to `crates/umbra-cli/src/tests.rs`:

```rust
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
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
cargo test -p umbra-cli parses_sync_force_full
```

Expected: compile fails because `force_full` does not exist.

- [ ] **Step 3: Add sync argument**

In `crates/umbra-cli/src/main.rs`, update `SyncCommand::Run`:

```rust
Run {
    #[arg(long = "vault", alias = "vault-id")]
    vault_id: VaultId,
    #[arg(long)]
    since_vault_revision: Option<RevisionId>,
    #[arg(long)]
    force_full: bool,
},
```

- [ ] **Step 4: Update sync handler cursor logic**

In `crates/umbra-cli/src/commands.rs`, update the sync branch pattern:

```rust
Command::Sync(SyncCommand::Run {
    vault_id,
    since_vault_revision,
    force_full,
}) => {
```

Replace cursor selection with:

```rust
let cache = crate::cache::LocalCache::open(&config.active_profile)?;
let since_vault_revision = if force_full {
    0
} else if let Some(value) = since_vault_revision {
    value
} else {
    cache.latest_vault_revision(vault_id)?.unwrap_or(0)
};
```

Remove the later duplicate `let cache = crate::cache::LocalCache::open(&config.active_profile)?;`.

- [ ] **Step 5: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli parses_sync_force_full
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli
git commit -m "feat(cli): use cached sync cursors"
```

---

### Task 6: Document Cache Behavior

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol.md`
- Modify: `docs/threat-model.md`

- [ ] **Step 1: Update README cache usage**

Append to `README.md`:

```markdown
## Local CLI Cache

The CLI stores a per-profile SQLite cache under the local Umbra data directory.

The cache contains encrypted envelopes, key wrappings, sync cursors, and metadata. It does not contain plaintext secrets or plaintext vault keys.

Useful commands:

```bash
umbra sync run --vault "$VAULT_ID"
umbra cache status
umbra item list --vault-id "$VAULT_ID" --cached
umbra item get --vault-id "$VAULT_ID" --item-id "$ITEM_ID" --cached
```

`sync run` uses the cached vault revision cursor by default. Use `--force-full` to request from revision `0`.
```

- [ ] **Step 2: Update protocol docs**

Append to `docs/protocol.md`:

```markdown
## Cacheable Sync Data

`SyncResponse` is safe for the CLI to cache because item data and vault keys are still encrypted envelopes.

The client may persist:

- `latest_vault_revision`;
- item revision envelopes;
- vault key wrapping envelopes;
- item ids, vault ids, revision numbers, and key generation metadata.

The server remains the source of truth. The cache is a local acceleration and offline inspection layer, not an authority for membership or writes.
```

- [ ] **Step 3: Update threat model**

Append to `docs/threat-model.md`:

```markdown
## Local SQLite Cache

The first CLI cache stores encrypted envelopes and metadata in SQLite.

It does not store plaintext secrets, plaintext vault keys, or master passwords.

A local attacker who steals the cache can see metadata such as vault ids, item ids, revision counts, timestamps, and any non-secret names stored outside envelopes. They still need client-side key material to decrypt item contents.

Future work may encrypt sensitive metadata or the full SQLite database with a local cache key.
```

- [ ] **Step 4: Run docs-adjacent checks and commit**

Run:

```bash
cargo fmt --all --check
cargo test -p umbra-cli
```

Expected: pass.

Commit:

```bash
git add README.md docs/protocol.md docs/threat-model.md
git commit -m "docs(cli): document local cache"
```

---

### Task 7: Final Verification And Push

**Files:**
- No source changes expected.

- [ ] **Step 1: Run full verification**

Run:

```bash
cargo fmt --all --check
cargo test --all
cargo build
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

Expected: all commands pass.

- [ ] **Step 2: Inspect commits and status**

Run:

```bash
git status --short --branch
git log --oneline -12
```

Expected: clean working tree and commits for schema, sync persistence, cache status, cached item commands, sync cursor, docs.

- [ ] **Step 3: Push and watch CI**

Run:

```bash
git push origin main
gh run list --limit 3
gh run watch <new-run-id> --exit-status
```

Expected: CI passes formatting, tests with PostgreSQL, build, and clippy.

---

## Self-Review

Spec coverage:

- Local cache: covered by `LocalCache`, SQLite schema, and per-profile cache path.
- SQLite decision: covered with `rusqlite` and bundled SQLite.
- Zero-knowledge boundary: covered by storing encrypted envelopes only and documenting metadata leakage.
- CLI usability: covered by `cache status`, cached item list/get, and sync cursor behavior.
- Server/CLI next gap: determined as CLI cache; server changes are not required for this first cache step.

Known gaps intentionally left for later:

- cache encryption with SQLCipher or local cache key;
- item plaintext decrypt/get UX;
- local unlock/lock state;
- offline mutation queue;
- conflict resolution;
- background sync.

Placeholder scan:

- No deferred-work markers are present.
- Every code-changing task includes concrete code snippets and commands.

Type consistency:

- Uses `uuid::Uuid` for vault/item/user/device IDs.
- Uses `RevisionId`/`i64` revision values consistently with current protocol.
- Uses current `SyncResponse`, `VaultSyncChanges`, `ItemRevisionResponse`, and `VaultKeyWrappingResponse`.
