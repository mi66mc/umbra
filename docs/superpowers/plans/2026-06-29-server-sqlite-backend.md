# Server SQLite Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `umbra-server` run against either PostgreSQL or a local SQLite file so dev/test runs do not require a Postgres container.

**Architecture:** Keep PostgreSQL as the production default and add SQLite as a first-class development backend. Introduce a storage backend boundary, keep the existing Postgres SQL intact, then add SQLite migrations and SQLite query implementations behind the same storage API. Avoid `sqlx::AnyPool` because the current code uses backend-specific SQL syntax and row types.

**Tech Stack:** Rust 1.88, SQLx Postgres, SQLx SQLite, async trait dispatch, Axum server, existing `umbra-storage`, `umbra-migrations`, `umbra-server`.

---

## File Structure

- Modify `Cargo.toml`: add SQLx `sqlite` feature at workspace level.
- Modify `crates/umbra-storage/Cargo.toml`: add `async-trait`.
- Modify `crates/umbra-migrations/Cargo.toml`: use SQLx SQLite feature through workspace.
- Modify `crates/umbra-server/src/config.rs`: add `database.backend` with `postgres` and `sqlite`.
- Modify `crates/umbra-server/src/server.rs`: choose the storage backend from config.
- Modify `crates/umbra-server/src/state.rs`: store a backend-agnostic storage handle.
- Create `crates/umbra-storage/src/backend.rs`: trait and enum/shared handle for storage operations.
- Create `crates/umbra-storage/src/postgres/mod.rs`: current Postgres storage implementation.
- Create `crates/umbra-storage/src/sqlite/mod.rs`: SQLite storage implementation.
- Create `crates/umbra-storage/src/sqlite/convert.rs`: SQLite row conversion helpers.
- Create `crates/umbra-migrations/sqlite/000001_initial_schema.sql` through `000005_device_trust_state.sql`: SQLite schema equivalent to current Postgres migrations.
- Modify `crates/umbra-migrations/src/lib.rs`: expose Postgres and SQLite migrators/status.
- Modify `README.md`, `docs/migrations.md`, `docs/architecture.md`: document SQLite dev mode.

## Design Decisions

- Config shape:

```toml
[database]
backend = "postgres"
url = "postgres://umbra:umbra@localhost:5432/umbra"
max_connections = 10
```

SQLite dev example:

```toml
[database]
backend = "sqlite"
url = "sqlite://./umbra-dev.db?mode=rwc"
max_connections = 5
```

- `postgres` remains default.
- SQLite is explicitly supported for local dev and lightweight self-host; production recommendation remains Postgres until concurrency/backup guidance matures.
- Storage API remains async and backend-agnostic.
- SQLite schema stores JSON as `TEXT` with `json_valid(...)` checks where practical.
- SQLite timestamps are stored as RFC3339 `TEXT`.
- SQLite UUIDs are stored as `TEXT`.

---

### Task 1: Add Database Backend Config

**Files:**
- Modify: `crates/umbra-server/src/config.rs`
- Modify: `crates/umbra-server/src/server.rs`
- Test: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Write config parsing tests**

Add near the existing config tests in `crates/umbra-server/src/tests.rs`:

```rust
#[test]
fn database_backend_defaults_to_postgres() {
    let config = crate::config::AppConfig::default();

    assert_eq!(config.database.backend, crate::config::DatabaseBackend::Postgres);
    assert_eq!(config.database.url, "postgres://umbra:umbra@localhost:5432/umbra");
}

#[test]
fn database_backend_accepts_sqlite_from_toml() {
    let config: crate::config::AppConfig = toml::from_str(
        r#"
        [server]
        bind = "127.0.0.1:8080"

        [database]
        backend = "sqlite"
        url = "sqlite://./umbra-dev.db?mode=rwc"
        max_connections = 5

        [migrations]
        auto_migrate = true
        require_latest = true

        [security]
        session_ttl_minutes = 60

        [auth.opaque]
        allow_ephemeral_setup = true
        "#,
    )
    .unwrap();

    assert_eq!(config.database.backend, crate::config::DatabaseBackend::Sqlite);
    assert_eq!(config.database.url, "sqlite://./umbra-dev.db?mode=rwc");
    assert_eq!(config.database.max_connections, 5);
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cargo test -p umbra-server database_backend
```

Expected: compile failure because `DatabaseBackend` and `database.backend` do not exist.

- [ ] **Step 3: Add config enum**

In `crates/umbra-server/src/config.rs`, add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DatabaseBackend {
    Postgres,
    Sqlite,
}
```

Update `DatabaseSettings`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabaseSettings {
    pub(crate) backend: DatabaseBackend,
    pub(crate) url: String,
    pub(crate) max_connections: u32,
}
```

Update `Default for AppConfig`:

```rust
database: DatabaseSettings {
    backend: DatabaseBackend::Postgres,
    url: "postgres://umbra:umbra@localhost:5432/umbra".to_owned(),
    max_connections: 10,
},
```

Update `load_config` defaults:

```rust
.set_default("database.backend", "postgres")?
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p umbra-server database_backend
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-server/src/config.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): configure database backend"
```

---

### Task 2: Add Backend-Agnostic Storage Boundary

**Files:**
- Create: `crates/umbra-storage/src/backend.rs`
- Modify: `crates/umbra-storage/src/lib.rs`
- Modify: `crates/umbra-storage/Cargo.toml`
- Modify: `crates/umbra-server/src/state.rs`
- Modify: `crates/umbra-server/src/authz.rs`
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/signed_auth.rs`

- [ ] **Step 1: Add dependency**

In `crates/umbra-storage/Cargo.toml`, add:

```toml
async-trait = "0.1"
```

- [ ] **Step 2: Create storage trait**

Create `crates/umbra-storage/src/backend.rs`:

```rust
use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    AppendAuditLog, ApprovePendingDevice, AuditLogRecord, CreateDevice, CreateEncryptedItem,
    CreateItemRevision, CreateOrg, CreateRecoveryChallenge, CreateSession, CreateUser,
    CreateVault, CreateVaultKeyWrapping, DeviceRecord, FinishVaultKeyRotation,
    ItemRevisionRecord, OrgMemberRecord, OrgRecord, RecoveryChallengeRecord,
    RotationStatusRecord, SessionRecord, StorageError, UpsertOrgMember, UpsertUserAuth,
    UpsertVaultMember, UserAuthRecord, UserRecord, VaultKeyWrappingRecord, VaultMemberRecord,
    VaultRecord, VaultSyncStatusRecord,
};
use umbra_core::{DeviceId, OrgId, UserId, VaultId};

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError>;
    async fn find_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError>;
    async fn find_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError>;
    async fn upsert_user_auth(&self, input: UpsertUserAuth) -> Result<UserAuthRecord, StorageError>;
    async fn find_user_auth(&self, user_id: UserId) -> Result<UserAuthRecord, StorageError>;

    async fn create_device(&self, input: CreateDevice) -> Result<DeviceRecord, StorageError>;
    async fn list_devices_for_user(&self, user_id: UserId) -> Result<Vec<DeviceRecord>, StorageError>;
    async fn find_device_by_id(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError>;
    async fn list_pending_devices_for_user(&self, user_id: UserId) -> Result<Vec<DeviceRecord>, StorageError>;
    async fn find_pending_device_by_approval_hash(&self, user_id: UserId, approval_code_hash: &str) -> Result<DeviceRecord, StorageError>;
    async fn approve_pending_device(&self, input: ApprovePendingDevice) -> Result<DeviceRecord, StorageError>;
    async fn mark_device_trusted(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError>;
    async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError>;
    async fn create_recovery_challenge(&self, input: CreateRecoveryChallenge) -> Result<RecoveryChallengeRecord, StorageError>;
    async fn consume_recovery_challenge(&self, challenge_id: Uuid, user_id: UserId, device_id: DeviceId, challenge_hash: &str) -> Result<RecoveryChallengeRecord, StorageError>;

    async fn create_session(&self, input: CreateSession) -> Result<SessionRecord, StorageError>;
    async fn find_active_session_by_hash(&self, token_hash: &str) -> Result<SessionRecord, StorageError>;
    async fn find_active_session_by_id(&self, session_id: Uuid) -> Result<SessionRecord, StorageError>;
    async fn record_session_nonce(&self, session_id: Uuid, nonce: &str) -> Result<(), StorageError>;
    async fn revoke_sessions_for_device(&self, device_id: Uuid) -> Result<u64, StorageError>;

    async fn create_org(&self, input: CreateOrg) -> Result<OrgRecord, StorageError>;
    async fn find_org_by_id(&self, org_id: OrgId) -> Result<OrgRecord, StorageError>;
    async fn list_orgs_for_user(&self, user_id: UserId) -> Result<Vec<OrgRecord>, StorageError>;
    async fn upsert_org_member(&self, input: UpsertOrgMember) -> Result<OrgMemberRecord, StorageError>;
    async fn list_org_members(&self, org_id: OrgId) -> Result<Vec<OrgMemberRecord>, StorageError>;
    async fn find_org_member(&self, org_id: OrgId, user_id: UserId) -> Result<OrgMemberRecord, StorageError>;

    async fn create_vault(&self, input: CreateVault) -> Result<VaultRecord, StorageError>;
    async fn find_vault_by_id(&self, vault_id: VaultId) -> Result<VaultRecord, StorageError>;
    async fn list_vaults_for_user(&self, user_id: UserId) -> Result<Vec<VaultRecord>, StorageError>;
    async fn upsert_vault_member(&self, input: UpsertVaultMember) -> Result<VaultMemberRecord, StorageError>;
    async fn list_vault_members(&self, vault_id: VaultId) -> Result<Vec<VaultMemberRecord>, StorageError>;
    async fn has_active_vault_membership(&self, vault_id: VaultId, user_id: UserId) -> Result<bool, StorageError>;
    async fn create_vault_key_wrapping(&self, input: CreateVaultKeyWrapping) -> Result<VaultKeyWrappingRecord, StorageError>;
    async fn list_key_wrappings_for_user_vault(&self, user_id: UserId, vault_id: VaultId) -> Result<Vec<VaultKeyWrappingRecord>, StorageError>;
    async fn revoke_vault_member(&self, vault_id: VaultId, user_id: UserId) -> Result<(), StorageError>;
    async fn revoke_key_wrapping(&self, wrapping_id: Uuid) -> Result<(), StorageError>;
    async fn rotation_status(&self, vault_id: VaultId) -> Result<RotationStatusRecord, StorageError>;
    async fn vault_sync_status(&self, vault_id: VaultId, user_id: UserId) -> Result<VaultSyncStatusRecord, StorageError>;
    async fn finish_vault_key_rotation(&self, input: FinishVaultKeyRotation) -> Result<RotationStatusRecord, StorageError>;

    async fn create_item_revision(&self, input: CreateItemRevision) -> Result<ItemRevisionRecord, StorageError>;
    async fn create_item(&self, input: CreateEncryptedItem) -> Result<ItemRevisionRecord, StorageError>;
    async fn list_item_revisions_since(&self, vault_id: VaultId, since_vault_revision: i64) -> Result<Vec<ItemRevisionRecord>, StorageError>;

    async fn append_audit_log(&self, input: AppendAuditLog) -> Result<AuditLogRecord, StorageError>;
}
```

- [ ] **Step 3: Export trait**

In `crates/umbra-storage/src/lib.rs`, add:

```rust
mod backend;
pub use backend::StorageBackend;
```

- [ ] **Step 4: Implement trait for existing `Storage`**

Create `impl StorageBackend for Storage` in `crates/umbra-storage/src/backend.rs` by delegating each trait method to the existing inherent method:

```rust
#[async_trait]
impl StorageBackend for crate::Storage {
    async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError> {
        crate::Storage::create_user(self, input).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError> {
        crate::Storage::find_user_by_email(self, email).await
    }
}
```

Add one delegation method for each trait method declared in `StorageBackend`. The body must call the same-named inherent method on `crate::Storage`. This task is intentionally mechanical and must not change SQL.

- [ ] **Step 5: Change `AppState` storage handle**

In `crates/umbra-server/src/state.rs`, replace:

```rust
use umbra_storage::Storage;
pub(crate) storage: Storage,
```

with:

```rust
use std::sync::Arc;
use umbra_storage::StorageBackend;
pub(crate) storage: Arc<dyn StorageBackend>,
```

In test helpers, wrap storage with `Arc::new(storage)`.

- [ ] **Step 6: Run compiler-driven fixes**

Run:

```bash
cargo check -p umbra-server
```

Expected first run: compile errors where direct `Storage` type assumptions remain. Fix by passing/cloning `Arc<dyn StorageBackend>` instead of `Storage`.

- [ ] **Step 7: Run tests**

Run:

```bash
cargo test -p umbra-server
cargo test -p umbra-storage
```

Expected: all current tests still pass or Postgres-specific tests skip when `UMBRA_TEST_DATABASE_URL` is unset.

- [ ] **Step 8: Commit**

```bash
git add crates/umbra-storage crates/umbra-server
git commit -m "refactor(storage): introduce backend abstraction"
```

---

### Task 3: Split Existing Postgres Storage Without Behavior Change

**Files:**
- Create: `crates/umbra-storage/src/postgres/mod.rs`
- Move/Modify: `crates/umbra-storage/src/users.rs`
- Move/Modify: `crates/umbra-storage/src/devices.rs`
- Move/Modify: `crates/umbra-storage/src/sessions.rs`
- Move/Modify: `crates/umbra-storage/src/orgs.rs`
- Move/Modify: `crates/umbra-storage/src/vaults.rs`
- Move/Modify: `crates/umbra-storage/src/items.rs`
- Move/Modify: `crates/umbra-storage/src/audit.rs`
- Move/Modify: `crates/umbra-storage/src/convert.rs`
- Modify: `crates/umbra-storage/src/lib.rs`

- [ ] **Step 1: Create Postgres module**

Create `crates/umbra-storage/src/postgres/mod.rs`:

```rust
mod audit;
mod convert;
mod devices;
mod items;
mod orgs;
mod sessions;
mod users;
mod vaults;

use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::StorageError;

#[derive(Clone)]
pub struct PostgresStorage {
    pub(crate) pool: PgPool,
}

impl PostgresStorage {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
```

- [ ] **Step 2: Move current SQL files into `postgres/`**

Move files:

```bash
git mv crates/umbra-storage/src/audit.rs crates/umbra-storage/src/postgres/audit.rs
git mv crates/umbra-storage/src/convert.rs crates/umbra-storage/src/postgres/convert.rs
git mv crates/umbra-storage/src/devices.rs crates/umbra-storage/src/postgres/devices.rs
git mv crates/umbra-storage/src/items.rs crates/umbra-storage/src/postgres/items.rs
git mv crates/umbra-storage/src/orgs.rs crates/umbra-storage/src/postgres/orgs.rs
git mv crates/umbra-storage/src/sessions.rs crates/umbra-storage/src/postgres/sessions.rs
git mv crates/umbra-storage/src/users.rs crates/umbra-storage/src/postgres/users.rs
git mv crates/umbra-storage/src/vaults.rs crates/umbra-storage/src/postgres/vaults.rs
```

- [ ] **Step 3: Replace type references**

In moved files, replace:

```rust
use crate::{Storage, StorageError};
impl Storage {
```

with:

```rust
use crate::{StorageError, postgres::PostgresStorage};
impl PostgresStorage {
```

In `postgres/convert.rs`, keep `sqlx::postgres::PgRow` row conversions unchanged.

- [ ] **Step 4: Preserve compatibility alias**

In `crates/umbra-storage/src/lib.rs`, replace the old `Storage` struct with:

```rust
mod backend;
mod error;
mod models;
pub mod postgres;

#[cfg(test)]
mod tests;

pub use backend::StorageBackend;
pub use error::StorageError;
pub use models::*;
pub use postgres::PostgresStorage;

pub type Storage = PostgresStorage;
```

- [ ] **Step 5: Move trait implementation target**

In `crates/umbra-storage/src/backend.rs`, change:

```rust
impl StorageBackend for crate::Storage
```

to:

```rust
impl StorageBackend for crate::postgres::PostgresStorage
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-storage
cargo test -p umbra-server
```

Expected: no behavior changes; tests pass or Postgres tests skip when env is unset.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-storage
git commit -m "refactor(storage): isolate postgres backend"
```

---

### Task 4: Add SQLite Migrations

**Files:**
- Create: `crates/umbra-migrations/sqlite/000001_initial_schema.sql`
- Create: `crates/umbra-migrations/sqlite/000002_org_access_and_key_rotation.sql`
- Create: `crates/umbra-migrations/sqlite/000003_signed_sessions.sql`
- Create: `crates/umbra-migrations/sqlite/000004_vault_access_revision.sql`
- Create: `crates/umbra-migrations/sqlite/000005_device_trust_state.sql`
- Modify: `crates/umbra-migrations/src/lib.rs`

- [ ] **Step 1: Add SQLite initial schema**

Create `crates/umbra-migrations/sqlite/000001_initial_schema.sql` with SQLite equivalents:

```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL CHECK (json_valid(encrypted_private_key)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    disabled_at TEXT
);

CREATE TABLE user_auth (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    auth_method TEXT NOT NULL,
    auth_data TEXT NOT NULL CHECK (json_valid(auth_data)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT,
    fingerprint TEXT NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at TEXT,
    revoked_at TEXT
);

CREATE TABLE orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at TEXT
);

CREATE TABLE org_members (
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    org_id TEXT REFERENCES orgs(id),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    created_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at TEXT,
    crypto_policy TEXT NOT NULL CHECK (json_valid(crypto_policy)),
    vault_revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE vault_members (
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (vault_id, user_id)
);

CREATE TABLE vault_key_wrappings (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES devices(id),
    wrapping_type TEXT NOT NULL,
    envelope TEXT NOT NULL CHECK (json_valid(envelope)),
    key_generation INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    rotated_at TEXT,
    revoked_at TEXT
);

CREATE TABLE items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    current_revision INTEGER NOT NULL,
    created_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at TEXT
);

CREATE TABLE item_revisions (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    vault_revision INTEGER NOT NULL,
    key_generation INTEGER NOT NULL DEFAULT 1,
    author_user_id TEXT REFERENCES users(id),
    envelope TEXT NOT NULL CHECK (json_valid(envelope)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (item_id, revision)
);

CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id),
    vault_id TEXT REFERENCES vaults(id),
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    metadata TEXT NOT NULL CHECK (json_valid(metadata)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
```

- [ ] **Step 2: Add SQLite migration 000002**

Create `crates/umbra-migrations/sqlite/000002_org_access_and_key_rotation.sql`:

```sql
ALTER TABLE vaults ADD COLUMN needs_key_rotation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN current_key_generation INTEGER NOT NULL DEFAULT 1;
CREATE INDEX vault_members_user_idx ON vault_members(user_id, state);
CREATE INDEX org_members_user_idx ON org_members(user_id, state);
CREATE INDEX vault_key_wrappings_user_vault_idx ON vault_key_wrappings(user_id, vault_id, revoked_at);
```

- [ ] **Step 3: Add SQLite migration 000003**

Create `crates/umbra-migrations/sqlite/000003_signed_sessions.sql`:

```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    auth_scheme TEXT NOT NULL DEFAULT 'bearer',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE UNIQUE INDEX sessions_token_hash_idx ON sessions(token_hash);

CREATE TABLE session_nonces (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (session_id, nonce)
);
```

- [ ] **Step 4: Add SQLite migration 000004**

Create `crates/umbra-migrations/sqlite/000004_vault_access_revision.sql`:

```sql
ALTER TABLE vaults ADD COLUMN access_revision INTEGER NOT NULL DEFAULT 1;
```

- [ ] **Step 5: Add SQLite migration 000005**

Create `crates/umbra-migrations/sqlite/000005_device_trust_state.sql`:

```sql
ALTER TABLE devices ADD COLUMN state TEXT;

UPDATE devices
SET state = CASE
    WHEN revoked_at IS NOT NULL THEN 'revoked'
    WHEN trusted = 1 THEN 'trusted'
    ELSE 'pending'
END;

ALTER TABLE devices ADD COLUMN approval_code_hash TEXT;
ALTER TABLE devices ADD COLUMN approval_expires_at TEXT;
ALTER TABLE devices ADD COLUMN bootstrap_public_key TEXT;
ALTER TABLE devices ADD COLUMN bootstrap_bundle TEXT CHECK (bootstrap_bundle IS NULL OR json_valid(bootstrap_bundle));
ALTER TABLE devices ADD COLUMN trusted_at TEXT;

UPDATE devices
SET trusted_at = created_at
WHERE state = 'trusted' AND trusted_at IS NULL;

CREATE INDEX devices_user_state_idx ON devices(user_id, state);
CREATE INDEX devices_approval_code_hash_idx ON devices(approval_code_hash)
    WHERE approval_code_hash IS NOT NULL;

CREATE TABLE device_recovery_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    challenge_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX device_recovery_challenges_device_idx
    ON device_recovery_challenges(device_id, expires_at)
    WHERE consumed_at IS NULL;
```

- [ ] **Step 6: Add migrator APIs**

In `crates/umbra-migrations/src/lib.rs`, replace single migrator with:

```rust
use sqlx::{PgPool, SqlitePool, migrate::Migrator};

pub static POSTGRES_MIGRATOR: Migrator = sqlx::migrate!("./migrations");
pub static SQLITE_MIGRATOR: Migrator = sqlx::migrate!("./sqlite");

pub async fn run_postgres(pool: &PgPool) -> Result<(), MigrationError> {
    POSTGRES_MIGRATOR.run(pool).await?;
    Ok(())
}

pub async fn run_sqlite(pool: &SqlitePool) -> Result<(), MigrationError> {
    SQLITE_MIGRATOR.run(pool).await?;
    Ok(())
}
```

Keep `run(pool: &PgPool)` as a compatibility wrapper calling `run_postgres`.

- [ ] **Step 7: Add SQLite status**

Add:

```rust
pub async fn status_sqlite(pool: &SqlitePool) -> Result<MigrationStatus, MigrationError> {
    let migration_table_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_one(pool)
    .await?;

    if migration_table_exists == 0 {
        return Ok(MigrationStatus::Pending);
    }

    let applied_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = true")
            .fetch_one(pool)
            .await?;

    if applied_count == SQLITE_MIGRATOR.iter().count() as i64 {
        Ok(MigrationStatus::Clean)
    } else {
        Ok(MigrationStatus::Pending)
    }
}
```

Keep `status(pool: &PgPool)` as a compatibility wrapper calling `status_postgres`.

- [ ] **Step 8: Update migration tests**

In `crates/umbra-migrations/src/lib.rs`, update `embeds_migrations`:

```rust
#[test]
fn embeds_postgres_and_sqlite_migrations() {
    assert_eq!(POSTGRES_MIGRATOR.iter().count(), 5);
    assert_eq!(SQLITE_MIGRATOR.iter().count(), 5);
}
```

- [ ] **Step 9: Run tests**

Run:

```bash
cargo test -p umbra-migrations
```

Expected: migration embedding test passes.

- [ ] **Step 10: Commit**

```bash
git add crates/umbra-migrations
git commit -m "feat(migrations): add sqlite schema"
```

---

### Task 5: Implement SQLite Storage Connection And Minimal Smoke Test

**Files:**
- Create: `crates/umbra-storage/src/sqlite/mod.rs`
- Create: `crates/umbra-storage/src/sqlite/convert.rs`
- Modify: `crates/umbra-storage/src/lib.rs`
- Modify: `crates/umbra-storage/src/tests.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Enable SQLx SQLite**

In workspace `Cargo.toml`, update `sqlx` features from:

```toml
features = ["runtime-tokio-rustls", "postgres", "uuid", "chrono", "json", "migrate", "macros"]
```

to:

```toml
features = ["runtime-tokio-rustls", "postgres", "sqlite", "uuid", "chrono", "json", "migrate", "macros"]
```

- [ ] **Step 2: Create SQLite storage type**

Create `crates/umbra-storage/src/sqlite/mod.rs`:

```rust
mod convert;

use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

use crate::StorageError;

#[derive(Clone)]
pub struct SqliteStorage {
    pub(crate) pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
```

- [ ] **Step 3: Export SQLite storage**

In `crates/umbra-storage/src/lib.rs`, add:

```rust
pub mod sqlite;
pub use sqlite::SqliteStorage;
```

- [ ] **Step 4: Add SQLite in-memory migration smoke test**

In `crates/umbra-storage/src/tests.rs`, add:

```rust
#[tokio::test]
async fn sqlite_migrations_create_required_schema() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();

    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let users_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'",
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    let devices_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'devices'",
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    assert_eq!(users_exists, 1);
    assert_eq!(devices_exists, 1);
}
```

- [ ] **Step 5: Run test**

Run:

```bash
cargo test -p umbra-storage sqlite_migrations_create_required_schema
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/umbra-storage crates/umbra-migrations
git commit -m "feat(storage): add sqlite connection"
```

---

### Task 6: Implement SQLite Users/Auth/Devices/Sessions

**Files:**
- Create: `crates/umbra-storage/src/sqlite/users.rs`
- Create: `crates/umbra-storage/src/sqlite/devices.rs`
- Create: `crates/umbra-storage/src/sqlite/sessions.rs`
- Modify: `crates/umbra-storage/src/sqlite/mod.rs`
- Modify: `crates/umbra-storage/src/sqlite/convert.rs`
- Modify: `crates/umbra-storage/src/backend.rs`
- Modify: `crates/umbra-storage/src/tests.rs`

- [ ] **Step 1: Add conversion helpers**

Create `crates/umbra-storage/src/sqlite/convert.rs` with:

```rust
use chrono::{DateTime, Utc};
use sqlx::{Row, sqlite::SqliteRow};
use uuid::Uuid;

use crate::{StorageError, UserRecord};

pub(crate) fn parse_uuid(value: String) -> Result<Uuid, StorageError> {
    Uuid::parse_str(&value).map_err(|_| StorageError::InvalidDatabaseValue {
        column: "uuid",
        value,
    })
}

pub(crate) fn parse_time(value: String) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| StorageError::InvalidDatabaseValue {
            column: "timestamp",
            value,
        })
}

pub(crate) fn optional_time(value: Option<String>) -> Result<Option<DateTime<Utc>>, StorageError> {
    value.map(parse_time).transpose()
}

pub(crate) fn json_value(value: String) -> Result<serde_json::Value, StorageError> {
    serde_json::from_str(&value).map_err(|_| StorageError::InvalidDatabaseValue {
        column: "json",
        value,
    })
}

pub(crate) fn user_from_row(row: SqliteRow) -> Result<UserRecord, StorageError> {
    Ok(UserRecord {
        id: parse_uuid(row.try_get("id")?)?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        public_key: row.try_get("public_key")?,
        encrypted_private_key: json_value(row.try_get("encrypted_private_key")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
        disabled_at: optional_time(row.try_get("disabled_at")?)?,
    })
}
```

Add these conversion functions in the same file, matching the field names in `models.rs`:

```rust
pub(crate) fn user_auth_from_row(row: SqliteRow) -> Result<UserAuthRecord, StorageError> {
    Ok(UserAuthRecord {
        user_id: parse_uuid(row.try_get("user_id")?)?,
        auth_method: row.try_get("auth_method")?,
        auth_data: json_value(row.try_get("auth_data")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
    })
}

pub(crate) fn device_from_row(row: SqliteRow) -> Result<DeviceRecord, StorageError> {
    let trusted: i64 = row.try_get("trusted")?;
    Ok(DeviceRecord {
        id: parse_uuid(row.try_get("id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        name: row.try_get("name")?,
        public_key: row.try_get("public_key")?,
        fingerprint: row.try_get("fingerprint")?,
        trusted: trusted != 0,
        state: crate::convert::str_to_device_state(row.try_get::<String, _>("state")?.as_str())?,
        approval_code_hash: row.try_get("approval_code_hash")?,
        approval_expires_at: optional_time(row.try_get("approval_expires_at")?)?,
        bootstrap_public_key: row.try_get("bootstrap_public_key")?,
        bootstrap_bundle: row
            .try_get::<Option<String>, _>("bootstrap_bundle")?
            .map(json_value)
            .transpose()?,
        trusted_at: optional_time(row.try_get("trusted_at")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
        last_seen_at: optional_time(row.try_get("last_seen_at")?)?,
        revoked_at: optional_time(row.try_get("revoked_at")?)?,
    })
}

pub(crate) fn session_from_row(row: SqliteRow) -> Result<SessionRecord, StorageError> {
    Ok(SessionRecord {
        id: parse_uuid(row.try_get("id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        device_id: row
            .try_get::<Option<String>, _>("device_id")?
            .map(parse_uuid)
            .transpose()?,
        token_hash: row.try_get("token_hash")?,
        auth_scheme: row.try_get("auth_scheme")?,
        created_at: parse_time(row.try_get("created_at")?)?,
        expires_at: parse_time(row.try_get("expires_at")?)?,
        revoked_at: optional_time(row.try_get("revoked_at")?)?,
    })
}

pub(crate) fn recovery_challenge_from_row(
    row: SqliteRow,
) -> Result<RecoveryChallengeRecord, StorageError> {
    Ok(RecoveryChallengeRecord {
        id: parse_uuid(row.try_get("id")?)?,
        user_id: parse_uuid(row.try_get("user_id")?)?,
        device_id: parse_uuid(row.try_get("device_id")?)?,
        challenge_hash: row.try_get("challenge_hash")?,
        expires_at: parse_time(row.try_get("expires_at")?)?,
        consumed_at: optional_time(row.try_get("consumed_at")?)?,
        created_at: parse_time(row.try_get("created_at")?)?,
    })
}
```

- [ ] **Step 2: Implement SQLite users**

Create `crates/umbra-storage/src/sqlite/users.rs`:

```rust
use crate::{
    CreateUser, StorageError, UpsertUserAuth, UserAuthRecord, UserRecord,
    error::map_sqlx_error,
    sqlite::{SqliteStorage, convert::{user_auth_from_row, user_from_row}},
};
use uuid::Uuid;

impl SqliteStorage {
    pub async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO users (id, email, display_name, public_key, encrypted_private_key)
            VALUES (?1, ?2, ?3, ?4, ?5)
            RETURNING id, email, display_name, public_key, encrypted_private_key,
                      created_at, updated_at, disabled_at
            "#,
        )
        .bind(id.to_string())
        .bind(input.email)
        .bind(input.display_name)
        .bind(input.public_key)
        .bind(input.encrypted_private_key.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        user_from_row(row)
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError> {
        let row = sqlx::query(
            "SELECT id, email, display_name, public_key, encrypted_private_key, created_at, updated_at, disabled_at FROM users WHERE email = ?1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        user_from_row(row)
    }
}
```

Implement `find_user_by_id`, `upsert_user_auth`, and `find_user_auth` in the same file using `?1` bindings and `RETURNING`.

- [ ] **Step 3: Implement SQLite devices and sessions**

Create `devices.rs` and `sessions.rs` with the same method names as the Postgres implementation. Translate SQL as follows:

```txt
$1, $2, $3       -> ?1, ?2, ?3
now()            -> strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
jsonb bind       -> bind(value.to_string())
uuid bind        -> bind(uuid.to_string())
trusted boolean  -> trusted INTEGER 0/1
```

For `record_session_nonce`, rely on the unique primary key and `map_sqlx_error` to convert duplicate nonce insertion into `StorageError::Conflict`.

- [ ] **Step 4: Implement trait delegation for SQLite**

In `crates/umbra-storage/src/backend.rs`, add:

```rust
#[async_trait]
impl StorageBackend for crate::sqlite::SqliteStorage {
    async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError> {
        crate::sqlite::SqliteStorage::create_user(self, input).await
    }

    async fn create_org(&self, _input: CreateOrg) -> Result<OrgRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation("sqlite create_org"))
    }
}
```

Add this error variant in `crates/umbra-storage/src/error.rs`:

```rust
#[error("operation is not supported by this storage backend: {0}")]
UnsupportedBackendOperation(&'static str),
```

- [ ] **Step 5: Add SQLite tests**

In `crates/umbra-storage/src/tests.rs`, add:

```rust
#[tokio::test]
async fn sqlite_users_devices_and_sessions_flow() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1).await.unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let user = create_test_user_on(&storage, "sqlite-user@example.com").await;
    let device = storage.create_device(CreateDevice {
        id: None,
        user_id: user.id,
        name: "sqlite laptop".to_owned(),
        public_key: Some("device-public-key".to_owned()),
        fingerprint: "SHA256:sqlite".to_owned(),
        state: DeviceState::Trusted,
        approval_code_hash: None,
        approval_expires_at: None,
        bootstrap_public_key: None,
    }).await.unwrap();

    let session = storage.create_session(CreateSession {
        id: None,
        user_id: user.id,
        device_id: Some(device.id),
        token_hash: "token-hash".to_owned(),
        auth_scheme: "signed".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
    }).await.unwrap();

    assert_eq!(storage.find_active_session_by_id(session.id).await.unwrap().device_id, Some(device.id));
    storage.record_session_nonce(session.id, "nonce-1").await.unwrap();
    assert!(matches!(storage.record_session_nonce(session.id, "nonce-1").await, Err(StorageError::Conflict)));
}
```

Create helper:

```rust
async fn create_test_user_on<S: StorageBackend + ?Sized>(storage: &S, email: &str) -> UserRecord {
    storage.create_user(CreateUser {
        id: None,
        email: email.to_owned(),
        display_name: Some("SQLite User".to_owned()),
        public_key: "user-public-key".to_owned(),
        encrypted_private_key: serde_json::json!({"ciphertext": "encrypted"}),
    }).await.unwrap()
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-storage sqlite_users_devices_and_sessions_flow
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-storage
git commit -m "feat(storage): implement sqlite auth storage"
```

---

### Task 7: Implement SQLite Org/Vault/Item/Audit Storage

**Files:**
- Create: `crates/umbra-storage/src/sqlite/orgs.rs`
- Create: `crates/umbra-storage/src/sqlite/vaults.rs`
- Create: `crates/umbra-storage/src/sqlite/items.rs`
- Create: `crates/umbra-storage/src/sqlite/audit.rs`
- Modify: `crates/umbra-storage/src/sqlite/mod.rs`
- Modify: `crates/umbra-storage/src/sqlite/convert.rs`
- Modify: `crates/umbra-storage/src/backend.rs`
- Modify: `crates/umbra-storage/src/tests.rs`

- [ ] **Step 1: Add row converters**

Extend `sqlite/convert.rs` with converters for:

```rust
org_from_row(row: SqliteRow) -> Result<OrgRecord, StorageError>
org_member_from_row(row: SqliteRow) -> Result<OrgMemberRecord, StorageError>
vault_from_row(row: SqliteRow) -> Result<VaultRecord, StorageError>
vault_member_from_row(row: SqliteRow) -> Result<VaultMemberRecord, StorageError>
vault_key_wrapping_from_row(row: SqliteRow) -> Result<VaultKeyWrappingRecord, StorageError>
item_revision_from_row(row: SqliteRow) -> Result<ItemRevisionRecord, StorageError>
audit_log_from_row(row: SqliteRow) -> Result<AuditLogRecord, StorageError>
```

Use the existing enum parsers from Postgres by moving enum string conversion helpers out of `postgres/convert.rs` into a shared `crates/umbra-storage/src/convert.rs`:

```rust
pub(crate) fn str_to_vault_kind(value: &str) -> Result<VaultKind, StorageError> {
    match value {
        "personal" => Ok(VaultKind::Personal),
        "shared" => Ok(VaultKind::Shared),
        "project" => Ok(VaultKind::Project),
        "org" => Ok(VaultKind::Org),
        value => Err(StorageError::InvalidDatabaseValue {
            column: "vaults.kind",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn str_to_vault_role(value: &str) -> Result<VaultRole, StorageError> {
    match value {
        "owner" => Ok(VaultRole::Owner),
        "admin" => Ok(VaultRole::Admin),
        "editor" => Ok(VaultRole::Editor),
        "viewer" => Ok(VaultRole::Viewer),
        value => Err(StorageError::InvalidDatabaseValue {
            column: "vault_members.role",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn str_to_member_state(value: &str) -> Result<MemberState, StorageError> {
    match value {
        "active" => Ok(MemberState::Active),
        "invited" => Ok(MemberState::Invited),
        "removed" => Ok(MemberState::Removed),
        value => Err(StorageError::InvalidDatabaseValue {
            column: "member.state",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn str_to_org_role(value: &str) -> Result<OrgRole, StorageError> {
    match value {
        "owner" => Ok(OrgRole::Owner),
        "admin" => Ok(OrgRole::Admin),
        "member" => Ok(OrgRole::Member),
        value => Err(StorageError::InvalidDatabaseValue {
            column: "org_members.role",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn str_to_device_state(value: &str) -> Result<DeviceState, StorageError> {
    match value {
        "pending" => Ok(DeviceState::Pending),
        "trusted" => Ok(DeviceState::Trusted),
        "revoked" => Ok(DeviceState::Revoked),
        value => Err(StorageError::InvalidDatabaseValue {
            column: "devices.state",
            value: value.to_owned(),
        }),
    }
}
```

- [ ] **Step 2: Implement SQLite orgs**

Create `sqlite/orgs.rs` with `create_org`, `find_org_by_id`, `list_orgs_for_user`, `upsert_org_member`, `list_org_members`, and `find_org_member`. For `upsert_org_member`, use this SQL form:

```sql
INSERT INTO org_members (org_id, user_id, role, state)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(org_id, user_id) DO UPDATE SET
    role = excluded.role,
    state = excluded.state,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
RETURNING org_id, user_id, role, state, created_at, updated_at
```

- [ ] **Step 3: Implement SQLite vaults**

Create `sqlite/vaults.rs` with all vault and key wrapping methods. For `finish_vault_key_rotation`, use a transaction:

```rust
let mut tx = self.pool.begin().await?;
sqlx::query("UPDATE vaults SET current_key_generation = ?2, needs_key_rotation = 0, vault_revision = vault_revision + 1, access_revision = access_revision + 1 WHERE id = ?1 AND current_key_generation = ?3")
    .bind(input.vault_id.to_string())
    .bind(input.to_generation)
    .bind(input.from_generation)
    .execute(&mut *tx)
    .await?;
tx.commit().await?;
```

Insert new wrappings and item revisions inside the same transaction.

- [ ] **Step 4: Implement SQLite items**

Create `sqlite/items.rs` with `create_item`, `create_item_revision`, and `list_item_revisions_since`. Use a transaction for create/update revision so `items.current_revision` and `vaults.vault_revision` stay consistent.

- [ ] **Step 5: Implement SQLite audit**

Create `sqlite/audit.rs` with `append_audit_log`, binding `metadata.to_string()`.

- [ ] **Step 6: Complete trait delegation**

Replace each temporary `UnsupportedBackendOperation` branch in the SQLite `StorageBackend` impl with a one-to-one call to the corresponding `SqliteStorage` inherent method added in this task.

- [ ] **Step 7: Add SQLite full storage flow test**

In `crates/umbra-storage/src/tests.rs`, add:

```rust
#[tokio::test]
async fn sqlite_vault_item_and_rotation_flow() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1).await.unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let user = create_test_user_on(&storage, "sqlite-vault@example.com").await;
    let vault = storage.create_vault(CreateVault {
        id: None,
        org_id: None,
        name: "SQLite Personal".to_owned(),
        kind: VaultKind::Personal,
        created_by: Some(user.id),
        crypto_policy: serde_json::json!({"min_envelope_version": 1}),
    }).await.unwrap();

    storage.upsert_vault_member(UpsertVaultMember {
        vault_id: vault.id,
        user_id: user.id,
        role: VaultRole::Owner,
        state: MemberState::Active,
    }).await.unwrap();

    let revision = storage.create_item(CreateEncryptedItem {
        item_id: None,
        vault_id: vault.id,
        kind: ItemKind::Login,
        author_user_id: Some(user.id),
        envelope: serde_json::json!({"ciphertext": "encrypted"}),
    }).await.unwrap();

    assert_eq!(revision.revision, 1);
    assert_eq!(storage.list_item_revisions_since(vault.id, 0).await.unwrap().len(), 1);
    assert!(storage.has_active_vault_membership(vault.id, user.id).await.unwrap());
}
```

- [ ] **Step 8: Run tests**

Run:

```bash
cargo test -p umbra-storage sqlite_vault_item_and_rotation_flow
cargo test -p umbra-storage
```

Expected: SQLite tests pass; Postgres tests pass or skip depending on env.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-storage
git commit -m "feat(storage): implement sqlite vault storage"
```

---

### Task 8: Wire SQLite Into Server Runtime

**Files:**
- Modify: `crates/umbra-server/src/server.rs`
- Modify: `crates/umbra-server/src/state.rs`
- Modify: `crates/umbra-server/src/tests.rs`
- Modify: `crates/umbra-server/src/error.rs`

- [ ] **Step 1: Update server connection**

In `crates/umbra-server/src/server.rs`, replace Postgres-only `connect_storage` with:

```rust
use std::sync::Arc;
use umbra_storage::{PostgresStorage, SqliteStorage, StorageBackend};

use crate::config::{AppConfig, DatabaseBackend};

pub(crate) enum ConnectedStorage {
    Postgres(PostgresStorage),
    Sqlite(SqliteStorage),
}

impl ConnectedStorage {
    pub(crate) fn backend(self) -> Arc<dyn StorageBackend> {
        match self {
            ConnectedStorage::Postgres(storage) => Arc::new(storage),
            ConnectedStorage::Sqlite(storage) => Arc::new(storage),
        }
    }
}

pub(crate) async fn connect_storage(config: &AppConfig) -> Result<ConnectedStorage, ServerError> {
    match config.database.backend {
        DatabaseBackend::Postgres => Ok(ConnectedStorage::Postgres(
            PostgresStorage::connect(&config.database.url, config.database.max_connections).await?,
        )),
        DatabaseBackend::Sqlite => Ok(ConnectedStorage::Sqlite(
            SqliteStorage::connect(&config.database.url, config.database.max_connections).await?,
        )),
    }
}
```

- [ ] **Step 2: Add migration helpers**

In `server.rs`, add:

```rust
async fn run_migrations(storage: &ConnectedStorage) -> Result<(), ServerError> {
    match storage {
        ConnectedStorage::Postgres(storage) => umbra_migrations::run_postgres(storage.pool()).await?,
        ConnectedStorage::Sqlite(storage) => umbra_migrations::run_sqlite(storage.pool()).await?,
    }
    Ok(())
}

async fn migration_status(storage: &ConnectedStorage) -> Result<MigrationStatus, ServerError> {
    Ok(match storage {
        ConnectedStorage::Postgres(storage) => umbra_migrations::status_postgres(storage.pool()).await?,
        ConnectedStorage::Sqlite(storage) => umbra_migrations::status_sqlite(storage.pool()).await?,
    })
}
```

Update `serve`, `migrate`, `migrate_status`, and `doctor` to use these helpers.

- [ ] **Step 3: Build AppState from backend**

In `serve`, after migrations:

```rust
let storage = storage.backend();
let state = AppState {
    config: config.clone(),
    storage,
    opaque_server_setup: Arc::new(opaque_setup),
    pending_logins: Arc::new(Mutex::new(HashMap::new())),
};
```

- [ ] **Step 4: Add server SQLite smoke test**

In `crates/umbra-server/src/tests.rs`, add:

```rust
#[tokio::test]
async fn sqlite_server_health_and_migration_status_work() {
    let mut config = AppConfig::default();
    config.database.backend = crate::config::DatabaseBackend::Sqlite;
    config.database.url = "sqlite::memory:".to_owned();
    config.migrations.auto_migrate = true;
    config.auth.opaque.allow_ephemeral_setup = true;

    let storage = crate::server::connect_storage(&config).await.unwrap();
    crate::server::run_migrations(&storage).await.unwrap();
    assert_eq!(crate::server::migration_status(&storage).await.unwrap(), umbra_migrations::MigrationStatus::Clean);
}
```

Make `run_migrations` and `migration_status` `pub(crate)` for tests.

- [ ] **Step 5: Run server tests**

Run:

```bash
cargo test -p umbra-server sqlite_server_health_and_migration_status_work
cargo test -p umbra-server
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-server
git commit -m "feat(server): support sqlite database backend"
```

---

### Task 9: Add Dev Defaults And Docs

**Files:**
- Modify: `README.md`
- Modify: `docs/migrations.md`
- Modify: `docs/architecture.md`
- Modify: `.env.example`

- [ ] **Step 1: Add README SQLite quickstart**

In `README.md`, add after Development:

```markdown
### SQLite dev server

For local development without Postgres:

```bash
$env:UMBRA__DATABASE__BACKEND="sqlite"
$env:UMBRA__DATABASE__URL="sqlite://./umbra-dev.db?mode=rwc"
$env:UMBRA__MIGRATIONS__AUTO_MIGRATE="true"
$env:UMBRA__AUTH__OPAQUE__ALLOW_EPHEMERAL_SETUP="true"
cargo run -p umbra-server -- serve
```

SQLite is convenient for local dev and lightweight single-node testing. PostgreSQL remains the recommended production backend.
```

- [ ] **Step 2: Add env example**

In `.env.example`, add:

```txt
# PostgreSQL default
UMBRA__DATABASE__BACKEND=postgres
UMBRA__DATABASE__URL=postgres://umbra:umbra@localhost:5432/umbra

# Local SQLite alternative
# UMBRA__DATABASE__BACKEND=sqlite
# UMBRA__DATABASE__URL=sqlite://./umbra-dev.db?mode=rwc
```

- [ ] **Step 3: Update migrations docs**

In `docs/migrations.md`, add:

```markdown
## SQLite Migrations

`umbra-server migrate` runs the migration set matching `[database].backend`.

SQLite uses separate SQL migrations under `crates/umbra-migrations/sqlite/` because SQLite differs from PostgreSQL in JSON, timestamp, UUID, boolean, and DDL behavior.
```

- [ ] **Step 4: Update architecture docs**

In `docs/architecture.md`, change database section to:

```markdown
PostgreSQL is the production-default backend. SQLite is supported for local development and lightweight self-host testing through the same storage API, with separate migrations and backend-specific SQL.
```

- [ ] **Step 5: Commit**

```bash
git add README.md docs/migrations.md docs/architecture.md .env.example
git commit -m "docs(server): document sqlite backend"
```

---

### Task 10: Final Verification

**Files:**
- No code changes.

- [ ] **Step 1: Format check**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit 0.

- [ ] **Step 2: Workspace check**

Run:

```bash
cargo check --workspace
```

Expected: exit 0.

- [ ] **Step 3: Workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: exit 0.

- [ ] **Step 4: SQLite manual smoke**

Run:

```bash
$env:UMBRA__DATABASE__BACKEND="sqlite"
$env:UMBRA__DATABASE__URL="sqlite://./umbra-dev-smoke.db?mode=rwc"
$env:UMBRA__MIGRATIONS__AUTO_MIGRATE="true"
$env:UMBRA__AUTH__OPAQUE__ALLOW_EPHEMERAL_SETUP="true"
cargo run -p umbra-server -- migrate status
```

Expected output contains:

```txt
Clean
```

- [ ] **Step 5: Git status**

Run:

```bash
git status --short --branch
```

Expected: branch is ahead of origin only by this feature's commits, with no uncommitted files.

---

## Self-Review

**Spec coverage:** This plan adds a selectable `postgres`/`sqlite` server backend, keeps Postgres as default, adds SQLite migrations, implements SQLite storage, wires the server runtime, and documents how to run without a Postgres container.

**Risk:** This is a meaningful storage refactor. The safest implementation path is not to rewrite SQL generically; it is to isolate Postgres first, then add SQLite module-by-module with tests.

**Known intentional limitation:** SQLite is introduced as local/dev/lightweight backend. Production recommendation remains Postgres until backup/concurrency docs and operational testing are stronger.
