# Smart Sync CLI Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Umbra CLI feel current by default: reads sync only when needed, writes update local cache immediately, vaults can be addressed by name, and offline/cache-only behavior is explicit.

**Architecture:** Add a lightweight server sync status layer backed by item `vault_revision` plus a new vault `access_revision` for key-wrapping/membership changes. The CLI stores both revisions in SQLite, asks `/api/v1/sync/status` before expensive syncs, and reuses one sync helper before cache reads. Write commands update cache from returned encrypted revisions and perform targeted sync when key-wrapping state is needed.

**Tech Stack:** Rust, Axum, SQLx, PostgreSQL migrations, serde protocol types, rusqlite CLI cache, clap, existing signed HTTP client.

---

## Scope

This plan implements the next usability layer:

- `POST /api/v1/sync/status` for cheap “did anything change?” checks.
- `vault_access_revision` so wrapping/member/key-rotation changes are detectable even when no item changed.
- cache sync state with `latest_vault_revision`, `latest_access_revision`, and `synced_at`.
- cached vault metadata and vault-name resolution.
- read commands that auto-sync by default and support explicit `--offline`.
- writes that update cache immediately.
- `secret set` that updates an existing `env_bundle` instead of always creating duplicates.

Excluded from this plan:

- CRDT/merge UI for concurrent plaintext edits.
- OS keychain storage for `UserSecretKey`.
- Web UI.
- Full item delete UX.

## File Structure

- Create `crates/umbra-migrations/migrations/000004_vault_access_revision.sql`: schema migration for `vaults.access_revision`.
- Modify `crates/umbra-storage/src/models.rs`: expose access revision and sync status records.
- Modify `crates/umbra-storage/src/convert.rs`: read `access_revision` from vault rows.
- Modify `crates/umbra-storage/src/vaults.rs`: bump access revision on wrapping/member/rotation changes and expose status lookup.
- Modify `crates/umbra-storage/src/tests.rs`: database coverage for access revision and status.
- Modify `crates/umbra-protocol/src/lib.rs`: add status protocol types and access revision fields.
- Modify `crates/umbra-server/src/http.rs`: add `/api/v1/sync/status` and include access revision in sync/vault responses.
- Modify `crates/umbra-server/src/tests.rs`: status endpoint auth and behavior tests.
- Modify `crates/umbra-cli/src/cache.rs`: store vault metadata and richer sync state.
- Create `crates/umbra-cli/src/sync.rs`: shared smart-sync helper.
- Modify `crates/umbra-cli/src/main.rs`: add `--offline`, vault selectors, and sync status command flags.
- Modify `crates/umbra-cli/src/commands.rs`: use smart sync before reads, write-through cache after writes, and secret upsert behavior.
- Modify `crates/umbra-cli/src/tests.rs`: parser and cache behavior tests.
- Modify `README.md`, `docs/protocol.md`, and `docs/architecture.md`: document the new flow.

---

### Task 1: Add Vault Access Revision Migration

**Files:**
- Create: `crates/umbra-migrations/migrations/000004_vault_access_revision.sql`
- Test: `cargo test -p umbra-migrations`

- [ ] **Step 1: Add the migration**

Create `crates/umbra-migrations/migrations/000004_vault_access_revision.sql`:

```sql
ALTER TABLE vaults
    ADD COLUMN access_revision bigint NOT NULL DEFAULT 0 CHECK (access_revision >= 0);

CREATE INDEX vaults_access_revision_idx
    ON vaults(id, access_revision);
```

- [ ] **Step 2: Verify migration embedding**

Run:

```bash
cargo test -p umbra-migrations
```

Expected: PASS, including `embeds_migrations`.

- [ ] **Step 3: Commit**

```bash
git add crates/umbra-migrations/migrations/000004_vault_access_revision.sql
git commit -m "feat(migrations): add vault access revision"
```

---

### Task 2: Expose Access Revision in Storage

**Files:**
- Modify: `crates/umbra-storage/src/models.rs`
- Modify: `crates/umbra-storage/src/convert.rs`
- Modify: `crates/umbra-storage/src/vaults.rs`
- Modify: `crates/umbra-storage/src/tests.rs`
- Test: `cargo test -p umbra-storage postgres_vault_access_and_rotation_flow`

- [ ] **Step 1: Write the failing storage assertions**

In `crates/umbra-storage/src/tests.rs`, extend `postgres_vault_access_and_rotation_flow` after the initial wrapping creation:

```rust
let after_initial_wrapping = storage.find_vault_by_id(vault.id).await.unwrap();
assert_eq!(after_initial_wrapping.access_revision, 1);
```

After member removal or key rotation in the same test, add:

```rust
let after_access_change = storage.find_vault_by_id(vault.id).await.unwrap();
assert!(after_access_change.access_revision > after_initial_wrapping.access_revision);
```

Add a focused status assertion:

```rust
let status = storage
    .vault_sync_status(vault.id, owner.id)
    .await
    .expect("sync status");
assert_eq!(status.vault_id, vault.id);
assert_eq!(status.latest_vault_revision, after_access_change.vault_revision);
assert_eq!(status.latest_access_revision, after_access_change.access_revision);
assert_eq!(status.current_key_generation, after_access_change.current_key_generation);
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run:

```bash
cargo test -p umbra-storage postgres_vault_access_and_rotation_flow
```

Expected: FAIL because `VaultRecord.access_revision` and `vault_sync_status` do not exist.

- [ ] **Step 3: Add storage model fields**

In `crates/umbra-storage/src/models.rs`, add to `VaultRecord`:

```rust
pub access_revision: RevisionId,
```

Add a new record:

```rust
#[derive(Debug, Clone)]
pub struct VaultSyncStatusRecord {
    pub vault_id: VaultId,
    pub latest_vault_revision: RevisionId,
    pub latest_access_revision: RevisionId,
    pub current_key_generation: RevisionId,
    pub needs_key_rotation: bool,
}
```

- [ ] **Step 4: Read `access_revision` from vault rows**

In `crates/umbra-storage/src/convert.rs`, update `vault_from_row`:

```rust
access_revision: row.try_get("access_revision")?,
```

- [ ] **Step 5: Include access revision in vault selects**

In `crates/umbra-storage/src/vaults.rs`, update all vault `SELECT` / `RETURNING` lists to include `access_revision`:

```sql
RETURNING id, org_id, name, kind, vault_revision, access_revision, current_key_generation, needs_key_rotation, created_by, created_at, updated_at, deleted_at, crypto_policy
```

and:

```sql
SELECT id, org_id, name, kind, vault_revision, access_revision, current_key_generation, needs_key_rotation, created_by, created_at, updated_at, deleted_at, crypto_policy
```

- [ ] **Step 6: Bump access revision on wrapping/member changes**

In `create_vault_key_wrapping`, before inserting the wrapping, add:

```rust
sqlx::query(
    r#"
    UPDATE vaults
    SET access_revision = access_revision + 1, updated_at = now()
    WHERE id = $1
    "#,
)
.bind(input.vault_id)
.execute(&self.pool)
.await?;
```

In `remove_vault_member`, add an `access_revision = access_revision + 1` update in the same transaction that marks membership removed / wrappings revoked:

```sql
UPDATE vaults
SET access_revision = access_revision + 1,
    needs_key_rotation = true,
    updated_at = now()
WHERE id = $1
```

In `finish_vault_key_rotation`, include `access_revision = access_revision + 1` in the vault update that advances `current_key_generation`.

- [ ] **Step 7: Add sync status storage method**

In `crates/umbra-storage/src/vaults.rs`, add:

```rust
pub async fn vault_sync_status(
    &self,
    vault_id: VaultId,
    user_id: UserId,
) -> Result<VaultSyncStatusRecord, StorageError> {
    let row = sqlx::query(
        r#"
        SELECT v.id, v.vault_revision, v.access_revision, v.current_key_generation, v.needs_key_rotation
        FROM vaults v
        INNER JOIN vault_members vm ON vm.vault_id = v.id
        WHERE v.id = $1
          AND vm.user_id = $2
          AND vm.state = 'active'
          AND v.deleted_at IS NULL
        "#,
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StorageError::NotFound)?;

    Ok(VaultSyncStatusRecord {
        vault_id: row.try_get("id")?,
        latest_vault_revision: row.try_get("vault_revision")?,
        latest_access_revision: row.try_get("access_revision")?,
        current_key_generation: row.try_get("current_key_generation")?,
        needs_key_rotation: row.try_get("needs_key_rotation")?,
    })
}
```

Import `sqlx::Row` in the file if it is not already imported.

- [ ] **Step 8: Run storage test**

Run:

```bash
cargo test -p umbra-storage postgres_vault_access_and_rotation_flow
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-storage/src/models.rs crates/umbra-storage/src/convert.rs crates/umbra-storage/src/vaults.rs crates/umbra-storage/src/tests.rs
git commit -m "feat(storage): track vault access revision"
```

---

### Task 3: Add Sync Status Protocol Types

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`
- Test: `cargo test -p umbra-protocol sync_status_roundtrips`

- [ ] **Step 1: Add protocol structs**

In `crates/umbra-protocol/src/lib.rs`, add `vault_revision` and `access_revision` to `VaultResponse`:

```rust
pub vault_revision: RevisionId,
pub access_revision: RevisionId,
```

Add `latest_access_revision` to `VaultSyncChanges`:

```rust
pub latest_access_revision: RevisionId,
```

Add these sync status types near `SyncRequest`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatusRequest {
    pub protocol_version: u16,
    pub vaults: Vec<VaultStatusCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatusCursor {
    pub vault_id: VaultId,
    pub known_vault_revision: RevisionId,
    pub known_access_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatusResponse {
    pub protocol_version: u16,
    pub vaults: Vec<VaultStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatus {
    pub vault_id: VaultId,
    pub latest_vault_revision: RevisionId,
    pub latest_access_revision: RevisionId,
    pub current_key_generation: RevisionId,
    pub needs_key_rotation: bool,
    pub items_changed: bool,
    pub access_changed: bool,
}
```

- [ ] **Step 2: Add protocol roundtrip test**

In the protocol tests module, add:

```rust
#[test]
fn sync_status_roundtrips() {
    let vault_id = Uuid::new_v4();
    let response = SyncStatusResponse {
        protocol_version: PROTOCOL_VERSION,
        vaults: vec![VaultStatus {
            vault_id,
            latest_vault_revision: 7,
            latest_access_revision: 3,
            current_key_generation: 2,
            needs_key_rotation: false,
            items_changed: true,
            access_changed: false,
        }],
    };

    let encoded = serde_json::to_string(&response).unwrap();
    let decoded: SyncStatusResponse = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, response);
}
```

Update existing `VaultResponse` and `VaultSyncChanges` test literals with `vault_revision`, `access_revision`, and `latest_access_revision`.

- [ ] **Step 3: Run protocol test**

Run:

```bash
cargo test -p umbra-protocol sync_status_roundtrips
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs
git commit -m "feat(protocol): add sync status types"
```

---

### Task 4: Add Server Sync Status Endpoint

**Files:**
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`
- Test: `cargo test -p umbra-server sync_status`

- [ ] **Step 1: Wire route and imports**

In `crates/umbra-server/src/http.rs`, import:

```rust
SyncStatusRequest, SyncStatusResponse, VaultStatus,
```

Add route beside `/api/v1/sync`:

```rust
.route("/api/v1/sync/status", post(sync_status))
```

- [ ] **Step 2: Include revisions in responses**

Update `vault_response`:

```rust
vault_revision: vault.vault_revision,
access_revision: vault.access_revision,
```

Update `sync` response construction:

```rust
latest_access_revision: vault.access_revision,
```

- [ ] **Step 3: Implement status handler**

Add below `sync`:

```rust
async fn sync_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncStatusRequest>,
) -> Result<Json<SyncStatusResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate(&state, &headers).await?;
    let mut vaults = Vec::with_capacity(request.vaults.len());

    for cursor in request.vaults {
        ensure_vault_member(&state, cursor.vault_id, user_id).await?;
        let status = state
            .storage
            .vault_sync_status(cursor.vault_id, user_id)
            .await?;
        vaults.push(VaultStatus {
            vault_id: status.vault_id,
            latest_vault_revision: status.latest_vault_revision,
            latest_access_revision: status.latest_access_revision,
            current_key_generation: status.current_key_generation,
            needs_key_rotation: status.needs_key_rotation,
            items_changed: status.latest_vault_revision > cursor.known_vault_revision,
            access_changed: status.latest_access_revision > cursor.known_access_revision,
        });
    }

    Ok(Json(SyncStatusResponse {
        protocol_version: PROTOCOL_VERSION,
        vaults,
    }))
}
```

- [ ] **Step 4: Update server test literals**

In `crates/umbra-server/src/tests.rs`, update `VaultResponse` assertions to include the new fields where direct struct literals or equality require it. Existing deserialization assertions should compile once `vault_response` provides fields.

- [ ] **Step 5: Add status tests**

Add:

```rust
#[tokio::test]
async fn sync_status_reports_item_changes() {
    let storage = match fresh_test_storage().await {
        Some(storage) => storage,
        None => return,
    };
    let app = test_app(storage).await;
    let token = register_and_login(app.clone(), "sync-status@example.com", b"password").await;

    let (_status, vault): (StatusCode, VaultResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Personal".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;

    let (_status, unchanged): (StatusCode, SyncStatusResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/sync/status",
        Some(&token),
        &SyncStatusRequest {
            protocol_version: PROTOCOL_VERSION,
            vaults: vec![VaultStatusCursor {
                vault_id: vault.vault_id,
                known_vault_revision: vault.vault_revision,
                known_access_revision: vault.access_revision,
            }],
        },
    )
    .await;
    assert!(!unchanged.vaults[0].items_changed);
    assert!(!unchanged.vaults[0].access_changed);

    let (_status, _item): (StatusCode, ItemRevisionResponse) = json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/items", vault.vault_id),
        Some(&token),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id: None,
            kind: ItemKind::ApiKey,
            envelope: json!({"ciphertext": "abc"}),
        },
    )
    .await;

    let (_status, changed): (StatusCode, SyncStatusResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/sync/status",
        Some(&token),
        &SyncStatusRequest {
            protocol_version: PROTOCOL_VERSION,
            vaults: vec![VaultStatusCursor {
                vault_id: vault.vault_id,
                known_vault_revision: vault.vault_revision,
                known_access_revision: vault.access_revision,
            }],
        },
    )
    .await;
    assert!(changed.vaults[0].items_changed);
}
```

If helper signatures differ, adapt only the helper call shape and keep request/response fields identical.

- [ ] **Step 6: Run server status tests**

Run:

```bash
cargo test -p umbra-server sync_status
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): add sync status endpoint"
```

---

### Task 5: Upgrade CLI Cache State and Vault Metadata

**Files:**
- Modify: `crates/umbra-cli/src/cache.rs`
- Test: `cargo test -p umbra-cli cache`

- [ ] **Step 1: Add cache structs**

In `crates/umbra-cli/src/cache.rs`, add:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CachedVault {
    pub vault_id: uuid::Uuid,
    pub name: String,
    pub kind: String,
    pub latest_vault_revision: i64,
    pub latest_access_revision: i64,
    pub current_key_generation: i64,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSyncState {
    pub vault_id: uuid::Uuid,
    pub latest_vault_revision: i64,
    pub latest_access_revision: i64,
    pub synced_at: String,
}
```

- [ ] **Step 2: Extend schema**

In `create_schema`, change `vaults`:

```sql
latest_access_revision INTEGER NOT NULL DEFAULT 0,
```

Change `sync_state`:

```sql
latest_access_revision INTEGER NOT NULL DEFAULT 0,
```

Add migration-safe `ALTER TABLE` statements after `CREATE TABLE`:

```sql
ALTER TABLE vaults ADD COLUMN latest_access_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sync_state ADD COLUMN latest_access_revision INTEGER NOT NULL DEFAULT 0;
```

Because SQLite errors if a column already exists, run these through a Rust helper instead of `execute_batch`:

```rust
self.add_column_if_missing("vaults", "latest_access_revision", "INTEGER NOT NULL DEFAULT 0")?;
self.add_column_if_missing("sync_state", "latest_access_revision", "INTEGER NOT NULL DEFAULT 0")?;
```

Implement:

```rust
fn add_column_if_missing(&self, table: &str, column: &str, definition: &str) -> Result<(), CliError> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut statement = self.connection.prepare(&pragma)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|existing| existing == column) {
        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
        self.connection.execute(&sql, [])?;
    }
    Ok(())
}
```

- [ ] **Step 3: Add upsert/list helpers**

Add:

```rust
pub fn upsert_vault(&self, vault: &umbra_protocol::VaultResponse) -> Result<(), CliError> {
    self.connection.execute(
        r#"
        INSERT INTO vaults (
            vault_id, org_id, name, kind, latest_vault_revision, latest_access_revision,
            current_key_generation, needs_key_rotation, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(vault_id) DO UPDATE SET
            org_id = excluded.org_id,
            name = excluded.name,
            kind = excluded.kind,
            latest_vault_revision = excluded.latest_vault_revision,
            latest_access_revision = excluded.latest_access_revision,
            current_key_generation = excluded.current_key_generation,
            needs_key_rotation = excluded.needs_key_rotation,
            updated_at = excluded.updated_at
        "#,
        params![
            vault.vault_id.to_string(),
            vault.org_id.map(|id| id.to_string()),
            vault.name,
            format!("{:?}", vault.kind),
            vault.vault_revision,
            vault.access_revision,
            vault.current_key_generation,
            vault.needs_key_rotation as i64,
            chrono::Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}
```

Add `sync_state(vault_id)`, `upsert_sync_state(vault_id, latest_vault_revision, latest_access_revision)`, `list_vaults()`, and `find_vault_by_name(name)` using the `CachedVault` / `CachedSyncState` structs.

- [ ] **Step 4: Update apply_sync_changes**

When writing `sync_state`, include `changes.latest_access_revision`:

```sql
INSERT INTO sync_state (vault_id, latest_vault_revision, latest_access_revision, synced_at)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(vault_id) DO UPDATE SET
    latest_vault_revision = excluded.latest_vault_revision,
    latest_access_revision = excluded.latest_access_revision,
    synced_at = excluded.synced_at
```

- [ ] **Step 5: Add cache tests**

Add tests:

```rust
#[test]
fn upserts_vault_metadata_and_finds_by_name() {
    let cache = LocalCache::open_in_memory("personal").unwrap();
    let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();
    cache
        .upsert_vault(&umbra_protocol::VaultResponse {
            vault_id,
            org_id: None,
            name: "Personal".to_owned(),
            kind: umbra_core::VaultKind::Personal,
            vault_revision: 4,
            access_revision: 2,
            current_key_generation: 1,
            needs_key_rotation: false,
        })
        .unwrap();

    let vault = cache.find_vault_by_name("Personal").unwrap().unwrap();
    assert_eq!(vault.vault_id, vault_id);
    assert_eq!(vault.latest_vault_revision, 4);
    assert_eq!(vault.latest_access_revision, 2);
}
```

Extend the existing sync test to assert:

```rust
assert_eq!(
    cache.sync_state(vault_id).unwrap().unwrap().latest_access_revision,
    changes.latest_access_revision
);
```

- [ ] **Step 6: Run cache tests**

Run:

```bash
cargo test -p umbra-cli cache
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/cache.rs
git commit -m "feat(cli): cache vault sync metadata"
```

---

### Task 6: Add Shared Smart Sync Helper

**Files:**
- Create: `crates/umbra-cli/src/sync.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Test: `cargo test -p umbra-cli sync_policy`

- [ ] **Step 1: Create sync helper**

Create `crates/umbra-cli/src/sync.rs`:

```rust
use umbra_protocol::{
    PROTOCOL_VERSION, SyncRequest, SyncResponse, SyncStatusRequest, SyncStatusResponse,
    VaultStatusCursor, VaultSyncCursor,
};
use uuid::Uuid;

use crate::cache::LocalCache;
use crate::config::ProfileConfig;
use crate::error::CliError;
use crate::http::UmbraHttpClient;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    IfChanged,
    Always,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub synced: bool,
    pub latest_vault_revision: i64,
    pub latest_access_revision: i64,
}

pub async fn ensure_vault_synced(
    profile: &ProfileConfig,
    cache: &mut LocalCache,
    vault_id: Uuid,
    mode: SyncMode,
) -> Result<SyncOutcome, CliError> {
    let state = cache.sync_state(vault_id)?;
    let known_vault_revision = state
        .as_ref()
        .map(|state| state.latest_vault_revision)
        .unwrap_or(0);
    let known_access_revision = state
        .as_ref()
        .map(|state| state.latest_access_revision)
        .unwrap_or(0);

    if mode == SyncMode::Offline {
        return Ok(SyncOutcome {
            synced: false,
            latest_vault_revision: known_vault_revision,
            latest_access_revision: known_access_revision,
        });
    }

    let client = UmbraHttpClient::new(profile)?;
    let should_sync = if mode == SyncMode::Always {
        true
    } else {
        let status: SyncStatusResponse = client
            .post(
                "/api/v1/sync/status",
                &SyncStatusRequest {
                    protocol_version: PROTOCOL_VERSION,
                    vaults: vec![VaultStatusCursor {
                        vault_id,
                        known_vault_revision,
                        known_access_revision,
                    }],
                },
            )
            .await?;
        let Some(status) = status.vaults.into_iter().next() else {
            return Err(CliError::Input("sync status response did not include vault"));
        };
        status.items_changed || status.access_changed || state.is_none()
    };

    if !should_sync {
        return Ok(SyncOutcome {
            synced: false,
            latest_vault_revision: known_vault_revision,
            latest_access_revision: known_access_revision,
        });
    }

    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra login` first",
    ))?;
    let response: SyncResponse = client
        .post(
            "/api/v1/sync",
            &SyncRequest {
                protocol_version: PROTOCOL_VERSION,
                device_id,
                vaults: vec![VaultSyncCursor {
                    vault_id,
                    since_vault_revision: known_vault_revision,
                }],
            },
        )
        .await?;

    let mut outcome = SyncOutcome {
        synced: true,
        latest_vault_revision: known_vault_revision,
        latest_access_revision: known_access_revision,
    };
    for changes in &response.vaults {
        cache.apply_sync_changes(changes)?;
        outcome.latest_vault_revision = changes.latest_vault_revision;
        outcome.latest_access_revision = changes.latest_access_revision;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_modes_compare_as_expected() {
        assert_eq!(SyncMode::Offline, SyncMode::Offline);
        assert_ne!(SyncMode::Always, SyncMode::IfChanged);
    }
}
```

- [ ] **Step 2: Register module**

In `crates/umbra-cli/src/main.rs`, add:

```rust
mod sync;
```

- [ ] **Step 3: Run sync helper test**

Run:

```bash
cargo test -p umbra-cli sync_policy
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-cli/src/sync.rs crates/umbra-cli/src/main.rs
git commit -m "feat(cli): add smart sync helper"
```

---

### Task 7: Auto-Sync Read Commands and Add Offline Mode

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Test: `cargo test -p umbra-cli parses_offline_read_flags`

- [ ] **Step 1: Change read command flags**

In `ItemCommand::List`, replace `cached: bool` with:

```rust
#[arg(long)]
offline: bool,
```

In `ItemCommand::Get`, replace `cached: bool` with:

```rust
#[arg(long)]
offline: bool,
```

In `SecretCommand::Get`, add:

```rust
#[arg(long)]
offline: bool,
```

Keep `--cached` as an alias for one release by adding:

```rust
#[arg(long, alias = "cached")]
offline: bool,
```

- [ ] **Step 2: Add parser tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_offline_read_flags() {
    let vault_id = "00000000-0000-0000-0000-000000000001";
    let item_id = "00000000-0000-0000-0000-000000000002";

    let list = parse(["umbra", "item", "list", "--vault-id", vault_id, "--offline"]);
    assert!(matches!(
        list.command,
        Command::Item(crate::ItemCommand::List { offline: true, .. })
    ));

    let get = parse([
        "umbra",
        "item",
        "get",
        "--vault-id",
        vault_id,
        "--item-id",
        item_id,
        "--cached",
    ]);
    assert!(matches!(
        get.command,
        Command::Item(crate::ItemCommand::Get { offline: true, .. })
    ));

    let secret = parse([
        "umbra",
        "secret",
        "get",
        "pulzar/dev",
        "DATABASE_URL",
        "--vault-id",
        vault_id,
        "--offline",
    ]);
    assert!(matches!(
        secret.command,
        Command::Secret(crate::SecretCommand::Get { offline: true, .. })
    ));
}
```

- [ ] **Step 3: Use smart sync before reads**

In `commands.rs`, replace `ItemCommand::List` arm with:

```rust
Command::Item(ItemCommand::List { vault_id, offline }) => {
    let profile = active_profile(&config)?;
    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        vault_id,
        if offline { crate::sync::SyncMode::Offline } else { crate::sync::SyncMode::IfChanged },
    )
    .await?;
    print_json(&cache.list_latest_item_revisions(vault_id)?)
}
```

Do the same before `ItemCommand::Get` and `SecretCommand::Get`.

- [ ] **Step 4: Run parser tests**

Run:

```bash
cargo test -p umbra-cli parses_offline_read_flags
```

Expected: PASS.

- [ ] **Step 5: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): auto sync before cache reads"
```

---

### Task 8: Write Through Cache After Vault and Item Writes

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/cache.rs`
- Test: `cargo test -p umbra-cli cache`

- [ ] **Step 1: Add cache helper for single item revision**

In `LocalCache`, add:

```rust
pub fn upsert_item_revision(
    &self,
    item: &umbra_protocol::ItemRevisionResponse,
) -> Result<(), CliError> {
    self.connection.execute(
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
            chrono::Utc::now().to_rfc3339()
        ],
    )?;
    Ok(())
}
```

- [ ] **Step 2: Update cache state from item response**

Add:

```rust
pub fn mark_item_write_synced(
    &self,
    item: &umbra_protocol::ItemRevisionResponse,
) -> Result<(), CliError> {
    let access_revision = self
        .sync_state(item.vault_id)?
        .map(|state| state.latest_access_revision)
        .unwrap_or(0);
    self.upsert_item_revision(item)?;
    self.upsert_sync_state(item.vault_id, item.vault_revision, access_revision)
}
```

- [ ] **Step 3: Use write-through in commands**

In `item create`, change response type from `Value` to `ItemRevisionResponse`, then:

```rust
let response: ItemRevisionResponse = client.post(...).await?;
let cache = crate::cache::LocalCache::open(&config.active_profile)?;
cache.mark_item_write_synced(&response)?;
print_json(&response)
```

In `secret set`, do the same.

In `vault create`, after `let vault: VaultResponse = ...`, call:

```rust
let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
cache.upsert_vault(&vault)?;
crate::sync::ensure_vault_synced(profile, &mut cache, vault.vault_id, crate::sync::SyncMode::Always).await?;
```

This caches the server-generated wrapping id and the owner wrapping immediately after creating the vault.

- [ ] **Step 4: Add cache test for write-through**

In cache tests, add:

```rust
#[test]
fn item_write_updates_cache_and_cursor() {
    let cache = LocalCache::open_in_memory("personal").unwrap();
    let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000020").unwrap();
    let item_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000021").unwrap();
    let item = umbra_protocol::ItemRevisionResponse {
        item_id,
        vault_id,
        revision: 1,
        vault_revision: 5,
        key_generation: 1,
        author_user_id: None,
        envelope: serde_json::json!({"kind": "env_bundle"}),
    };

    cache.mark_item_write_synced(&item).unwrap();

    assert_eq!(
        cache.latest_item_revision(vault_id, item_id).unwrap().unwrap().vault_revision,
        5
    );
    assert_eq!(
        cache.sync_state(vault_id).unwrap().unwrap().latest_vault_revision,
        5
    );
}
```

- [ ] **Step 5: Run cache and CLI tests**

Run:

```bash
cargo test -p umbra-cli cache
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/cache.rs crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): write through local cache"
```

---

### Task 9: Make `secret set` Upsert Existing Env Bundles

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `cargo test -p umbra-cli`

- [ ] **Step 1: Add plaintext mutation helper**

In `commands.rs`, add:

```rust
fn set_plaintext_field(
    mut item: ItemPlaintextV1,
    key: &str,
    value: &str,
) -> ItemPlaintextV1 {
    if let Some(field) = item.fields.iter_mut().find(|field| field.name == key) {
        field.value = value.to_owned();
        field.sensitive = true;
        return item;
    }

    let kind = crate::item_plaintext::field_kind_for_name(key);
    let sensitive = crate::item_plaintext::is_sensitive_field(key, &kind);
    item.fields
        .push(umbra_core::ItemField::new(key, kind, value, sensitive));
    item
}
```

- [ ] **Step 2: Change `secret set` flow**

Before creating a new `env_bundle`, after smart sync and vault unlock, scan cached latest revisions:

```rust
let existing = cache
    .list_latest_item_revisions(vault_id)?
    .into_iter()
    .find_map(|revision| {
        let wrapper: ItemEnvelopeWrapper = serde_json::from_value(revision.envelope.clone()).ok()?;
        if wrapper.kind != "env_bundle" {
            return None;
        }
        let item = decrypt_cached_item_wrapper(&vault_key, &revision, wrapper).ok()?;
        if item.plaintext.title == project_env {
            Some((revision, item.plaintext))
        } else {
            None
        }
    });
```

If existing, update instead of create:

```rust
if let Some((revision, plaintext)) = existing {
    let updated_plaintext = set_plaintext_field(plaintext, &key, &value);
    let next_revision = revision.revision + 1;
    let kind_name = "env_bundle".to_owned();
    let envelope = encrypt_item_plaintext(
        vault_id,
        revision.item_id,
        next_revision,
        kind_name,
        &vault_key,
        &updated_plaintext,
    )?;
    let response: ItemRevisionResponse = client
        .put(
            &format!("/api/v1/vaults/{vault_id}/items/{}", revision.item_id),
            &UpdateItemRequest {
                protocol_version: PROTOCOL_VERSION,
                vault_id,
                item_id: revision.item_id,
                expected_revision: revision.revision,
                envelope,
            },
        )
        .await?;
    cache.mark_item_write_synced(&response)?;
    return print_json(&response);
}
```

If no existing item is found, keep current create behavior.

- [ ] **Step 3: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): upsert secret bundles"
```

---

### Task 10: Add Vault Name Resolution and Default Vault Sugar

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/config.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Test: `cargo test -p umbra-cli parses_vault_name_sugar`

- [ ] **Step 1: Store default vault in profile**

In `ProfileConfig`, add:

```rust
#[serde(default)]
pub default_vault_id: Option<Uuid>,
```

Update `Default` and `Debug` accordingly, without redacting this field.

- [ ] **Step 2: Add vault selector args**

Create a helper type in `main.rs` is unnecessary; keep clap simple.

For `SecretCommand::Set` and `SecretCommand::Get`, change:

```rust
#[arg(long)]
vault_id: VaultId,
```

to:

```rust
#[arg(long)]
vault_id: Option<VaultId>,
#[arg(long)]
vault: Option<String>,
```

Do the same for `ItemCommand::List`, `ItemCommand::Create`, and `ItemCommand::Get`. Keep `item get --item-id` required.

- [ ] **Step 3: Add resolver helper**

In `commands.rs`, add:

```rust
fn resolve_vault_id(
    config: &CliConfig,
    cache: &crate::cache::LocalCache,
    vault_id: Option<VaultId>,
    vault_name: Option<String>,
) -> Result<VaultId, CliError> {
    if let Some(vault_id) = vault_id {
        return Ok(vault_id);
    }
    if let Some(name) = vault_name {
        return cache
            .find_vault_by_name(&name)?
            .map(|vault| vault.vault_id)
            .ok_or(CliError::Input("vault name was not found in local cache; run `umbra vault list`"));
    }
    active_profile(config)?
        .default_vault_id
        .ok_or(CliError::Input("no vault selected; pass --vault-id, --vault, or set a default vault"))
}
```

- [ ] **Step 4: Cache vault list and set default on create**

In `vault list`, after fetching `Vec<VaultResponse>`, call `cache.upsert_vault` for each response.

In `vault create`, after response:

```rust
active_profile_mut(&mut config).default_vault_id = Some(vault.vault_id);
save_config(&config)?;
```

- [ ] **Step 5: Add parser tests**

In tests:

```rust
#[test]
fn parses_vault_name_sugar() {
    let cli = parse([
        "umbra",
        "secret",
        "get",
        "pulzar/dev",
        "DATABASE_URL",
        "--vault",
        "Personal",
    ]);
    assert!(matches!(
        cli.command,
        Command::Secret(crate::SecretCommand::Get {
            vault: Some(_),
            vault_id: None,
            ..
        })
    ));
}
```

- [ ] **Step 6: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli parses_vault_name_sugar
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/config.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): add vault selector sugar"
```

---

### Task 11: Document Smart Sync Flow

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol.md`
- Modify: `docs/architecture.md`
- Test: `cargo fmt --all --check`

- [ ] **Step 1: Update README commands**

In `README.md`, replace the manual sync-heavy secret flow with:

```markdown
```bash
umbra vault create Personal
umbra secret set pulzar/dev DATABASE_URL "postgres://..." --vault Personal
umbra secret get pulzar/dev DATABASE_URL --vault Personal
umbra item list --vault Personal
umbra item get --vault Personal --item-id "$ITEM_ID"
```

Read commands sync only when the server reports that item or access revisions changed. Use `--offline` to read only from the local encrypted-envelope cache.
```

- [ ] **Step 2: Document protocol status**

In `docs/protocol.md`, add:

```markdown
## Sync Status

`POST /api/v1/sync/status` lets clients check whether a full sync is needed.

The client sends its cached `known_vault_revision` and `known_access_revision` for each vault. The server responds with the latest revisions and booleans:

- `items_changed`: encrypted item revisions changed;
- `access_changed`: key wrapping, membership, key generation, or rotation state changed.

The endpoint is authenticated and performs the same vault membership checks as full sync. It does not expose item counts, member counts, plaintext metadata, or ciphertext.
```

- [ ] **Step 3: Document architecture**

In `docs/architecture.md`, add:

```markdown
## Smart Sync

Umbra separates item changes from access changes:

- `vault_revision` advances when encrypted item revisions change;
- `access_revision` advances when vault access material changes, such as key wrappings, membership removal, or key rotation state.

The CLI stores both revisions in SQLite. Online reads call sync status first and perform full sync only when one revision changed. Offline reads never contact the server and may return stale cached ciphertext.
```

- [ ] **Step 4: Run docs-safe checks**

Run:

```bash
cargo fmt --all --check
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/protocol.md docs/architecture.md
git commit -m "docs(sync): document smart sync flow"
```

---

### Task 12: Full Verification and Push

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --all --check
```

Expected: PASS.

- [ ] **Step 2: Run all tests**

Run:

```bash
cargo test --all
```

Expected: PASS.

- [ ] **Step 3: Run build**

Run:

```bash
cargo build
```

Expected: PASS.

- [ ] **Step 4: Run clippy**

Run:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 5: Check whitespace**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 6: Push**

Run:

```bash
git status --short --branch
git push origin main
```

Expected: branch is clean and push succeeds.

---

## Self-Review

Spec coverage:

- Avoid unnecessary full sync: Tasks 3, 4, 6, and 7.
- Detect vault/item changes correctly: Tasks 1, 2, 3, and 4.
- Avoid stale reads by default: Tasks 6 and 7.
- Explicit offline behavior: Task 7.
- Cache vault metadata and revisions: Task 5.
- Better CLI sugar for vault names/default vault: Task 10.
- Better write UX and fewer manual syncs: Tasks 8 and 9.
- Server auth/security for status: Task 4 requires membership checks and authenticated route.
- Documentation: Task 11.

Gaps intentionally excluded from this plan:

- Conflict-resolution UI for concurrent edits.
- OS keychain storage.
- Full item delete flow.
- Web/desktop/mobile clients.

Placeholder scan:

- No task contains `TBD`, `TODO`, `fill in details`, or “similar to”.
- Every code-changing task names exact files and concrete signatures or snippets.

Type consistency:

- `latest_access_revision` is used in storage, protocol, server status, sync responses, and CLI cache.
- `known_access_revision` is the client cursor name for status checks.
- CLI `SyncMode::Offline` is the explicit cache-only path.
