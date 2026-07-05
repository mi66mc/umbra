# Item Delete Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real encrypted item delete flow so users can delete vault items from the CLI and have deletions sync to other devices.

**Architecture:** Deletion is server-side metadata only: the server never decrypts item contents. Storage soft-deletes `items`, records the vault revision at which deletion happened, sync returns `deleted_items`, and the CLI removes deleted item revisions from the local encrypted cache. The delete API requires writer permission and optimistic concurrency via `expected_revision`.

**Tech Stack:** Rust, Clap, Axum, SQLx, PostgreSQL, SQLite, serde/serde_json, existing `umbra-storage`, `umbra-server`, `umbra-protocol`, and `umbra-cli`.

---

## Scope

Included:

- database migration adding `items.deleted_vault_revision`;
- storage method `delete_item`;
- storage method `list_deleted_item_ids_since`;
- server `DELETE /api/v1/vaults/:vault_id/items/:item_id`;
- sync `deleted_items` populated from storage;
- local cache removal for synced deletions;
- CLI `umbra item delete`;
- CLI destructive confirmation with `--yes`;
- tests across protocol, storage, server, CLI parser, cache, and docs.

Not included:

- restore/undelete;
- permanent purge;
- delete by secret key;
- conflict resolution UI beyond existing expected-revision conflict;
- plaintext deletion envelopes.

---

## File Structure

- Modify `crates/umbra-protocol/src/lib.rs`
  - Add a serialization test for existing `DeleteItemRequest`.

- Create `crates/umbra-migrations/migrations/000006_item_deletions.sql`
  - Add `deleted_vault_revision bigint` to Postgres `items`.

- Create `crates/umbra-migrations/sqlite/000006_item_deletions.sql`
  - Add `deleted_vault_revision integer` to SQLite `items`.

- Modify `crates/umbra-migrations/src/lib.rs`
  - Verify the new embedded migrations are included.

- Modify `crates/umbra-storage/src/models.rs`
  - Add `DeleteItem` and `DeletedItemRecord`.

- Modify `crates/umbra-storage/src/backend.rs`
  - Add trait methods for deleting items and listing deleted item ids.
  - Wire Postgres and SQLite implementations.

- Modify `crates/umbra-storage/src/postgres/items.rs`
  - Implement soft delete and deleted-id listing.
  - Exclude deleted items from item revision sync.

- Modify `crates/umbra-storage/src/sqlite/items.rs`
  - Implement the same behavior for SQLite.

- Modify `crates/umbra-storage/src/tests.rs`
  - Add shared backend tests for item deletion.

- Modify `crates/umbra-server/src/http.rs`
  - Add delete route/handler.
  - Populate sync `deleted_items`.

- Modify `crates/umbra-server/src/tests.rs`
  - Add HTTP test for delete and sync deletion propagation.

- Modify `crates/umbra-cli/src/http.rs`
  - Add signed `DELETE` with JSON body.

- Modify `crates/umbra-cli/src/cache.rs`
  - Delete cached item revisions when sync reports deletion.
  - Add direct cache deletion helper.

- Modify `crates/umbra-cli/src/main.rs`
  - Add `item delete` parser surface.

- Modify `crates/umbra-cli/src/tests.rs`
  - Add parser tests.

- Modify `crates/umbra-cli/src/commands.rs`
  - Implement `item delete`.

- Modify `README.md`, `docs/protocol.md`
  - Document item deletion and sync semantics.

---

## Task 1: Protocol Coverage For Delete Requests

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`

- [ ] **Step 1: Add protocol serialization test**

Inside the existing `#[cfg(test)] mod tests` in `crates/umbra-protocol/src/lib.rs`, add:

```rust
#[test]
fn delete_item_request_roundtrips() {
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let request = DeleteItemRequest {
        protocol_version: PROTOCOL_VERSION,
        vault_id,
        item_id,
        expected_revision: 7,
    };

    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["protocol_version"], json!(1));
    assert_eq!(encoded["vault_id"], json!(vault_id.to_string()));
    assert_eq!(encoded["item_id"], json!(item_id.to_string()));
    assert_eq!(encoded["expected_revision"], json!(7));

    let decoded: DeleteItemRequest = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, request);
}
```

- [ ] **Step 2: Run the protocol test**

Run:

```bash
cargo test -p umbra-protocol delete_item_request_roundtrips
```

Expected: PASS because `DeleteItemRequest` already exists and this task only locks down its wire shape.

- [ ] **Step 3: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs
git commit -m "test(protocol): cover delete item request"
```

---

## Task 2: Database Migrations For Deletion Revisions

**Files:**
- Create: `crates/umbra-migrations/migrations/000006_item_deletions.sql`
- Create: `crates/umbra-migrations/sqlite/000006_item_deletions.sql`
- Modify: `crates/umbra-migrations/src/lib.rs`

- [ ] **Step 1: Add failing migration embed assertions**

In `crates/umbra-migrations/src/lib.rs`, extend the existing `embeds_postgres_and_sqlite_migrations` test with:

```rust
assert!(
    POSTGRES_MIGRATOR
        .iter()
        .any(|migration| migration.version == 6 && migration.description == "item deletions")
);
assert!(
    SQLITE_MIGRATOR
        .iter()
        .any(|migration| migration.version == 6 && migration.description == "item deletions")
);
```

- [ ] **Step 2: Run migration embed test to verify it fails**

Run:

```bash
cargo test -p umbra-migrations embeds_postgres_and_sqlite_migrations
```

Expected: FAIL because migration version 6 does not exist yet.

- [ ] **Step 3: Create Postgres migration**

Create `crates/umbra-migrations/migrations/000006_item_deletions.sql`:

```sql
ALTER TABLE items
ADD COLUMN deleted_vault_revision bigint;

ALTER TABLE items
ADD CONSTRAINT items_deleted_vault_revision_positive
CHECK (deleted_vault_revision IS NULL OR deleted_vault_revision > 0);

CREATE INDEX items_deleted_vault_revision_idx
ON items(vault_id, deleted_vault_revision)
WHERE deleted_vault_revision IS NOT NULL;
```

- [ ] **Step 4: Create SQLite migration**

Create `crates/umbra-migrations/sqlite/000006_item_deletions.sql`:

```sql
ALTER TABLE items
ADD COLUMN deleted_vault_revision INTEGER;

CREATE INDEX items_deleted_vault_revision_idx
ON items(vault_id, deleted_vault_revision)
WHERE deleted_vault_revision IS NOT NULL;
```

- [ ] **Step 5: Run migration embed test**

Run:

```bash
cargo test -p umbra-migrations embeds_postgres_and_sqlite_migrations
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-migrations/src/lib.rs crates/umbra-migrations/migrations/000006_item_deletions.sql crates/umbra-migrations/sqlite/000006_item_deletions.sql
git commit -m "feat(migrations): add item deletion revision"
```

---

## Task 3: Storage Models And Trait Methods

**Files:**
- Modify: `crates/umbra-storage/src/models.rs`
- Modify: `crates/umbra-storage/src/backend.rs`

- [ ] **Step 1: Add storage model structs**

In `crates/umbra-storage/src/models.rs`, after `CreateItemRevision`, add:

```rust
#[derive(Debug, Clone)]
pub struct DeleteItem {
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub expected_revision: RevisionId,
    pub author_user_id: Option<UserId>,
}

#[derive(Debug, Clone)]
pub struct DeletedItemRecord {
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub deleted_vault_revision: RevisionId,
}
```

- [ ] **Step 2: Add trait methods**

In `crates/umbra-storage/src/backend.rs`, extend the top `use crate::{ ... }` list to include:

```rust
DeleteItem, DeletedItemRecord,
```

Add these methods to the `StorageBackend` trait after `create_item_revision`:

```rust
async fn delete_item(&self, input: DeleteItem) -> Result<DeletedItemRecord, StorageError>;
async fn list_deleted_item_ids_since(
    &self,
    vault_id: VaultId,
    since_vault_revision: i64,
) -> Result<Vec<DeletedItemRecord>, StorageError>;
```

Add these methods to the `impl StorageBackend for PostgresStorage` after `create_item_revision`:

```rust
async fn delete_item(&self, input: DeleteItem) -> Result<DeletedItemRecord, StorageError> {
    PostgresStorage::delete_item(self, input).await
}

async fn list_deleted_item_ids_since(
    &self,
    vault_id: VaultId,
    since_vault_revision: i64,
) -> Result<Vec<DeletedItemRecord>, StorageError> {
    PostgresStorage::list_deleted_item_ids_since(self, vault_id, since_vault_revision).await
}
```

Add these methods to the `impl StorageBackend for crate::sqlite::SqliteStorage` after `create_item_revision`:

```rust
async fn delete_item(&self, input: DeleteItem) -> Result<DeletedItemRecord, StorageError> {
    crate::sqlite::SqliteStorage::delete_item(self, input).await
}

async fn list_deleted_item_ids_since(
    &self,
    vault_id: VaultId,
    since_vault_revision: i64,
) -> Result<Vec<DeletedItemRecord>, StorageError> {
    crate::sqlite::SqliteStorage::list_deleted_item_ids_since(
        self,
        vault_id,
        since_vault_revision,
    )
    .await
}
```

- [ ] **Step 3: Run storage check to verify implementation is still missing**

Run:

```bash
cargo check -p umbra-storage
```

Expected: FAIL because `PostgresStorage::delete_item`, `PostgresStorage::list_deleted_item_ids_since`, `SqliteStorage::delete_item`, and `SqliteStorage::list_deleted_item_ids_since` do not exist yet.

- [ ] **Step 4: Commit model and trait surface**

Do not commit this task while `cargo check` fails. Continue directly to Task 4 before committing.

---

## Task 4: Storage Delete Implementations

**Files:**
- Modify: `crates/umbra-storage/src/postgres/items.rs`
- Modify: `crates/umbra-storage/src/sqlite/items.rs`
- Modify: `crates/umbra-storage/src/models.rs`
- Modify: `crates/umbra-storage/src/backend.rs`

- [ ] **Step 1: Implement Postgres soft delete**

In `crates/umbra-storage/src/postgres/items.rs`, add these methods inside `impl PostgresStorage` after `create_item_revision`:

```rust
pub async fn delete_item(
    &self,
    input: DeleteItem,
) -> Result<DeletedItemRecord, StorageError> {
    let mut tx = self.pool.begin().await?;

    let current_revision: i64 = sqlx::query_scalar(
        "SELECT current_revision FROM items WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL",
    )
    .bind(input.item_id)
    .bind(input.vault_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(StorageError::NotFound)?;

    if current_revision != input.expected_revision {
        return Err(StorageError::Conflict);
    }

    let vault_revision: i64 = sqlx::query_scalar(
        r#"
        UPDATE vaults
        SET vault_revision = vault_revision + 1, updated_at = now()
        WHERE id = $1
        RETURNING vault_revision
        "#,
    )
    .bind(input.vault_id)
    .fetch_one(&mut *tx)
    .await?;

    let affected = sqlx::query(
        r#"
        UPDATE items
        SET deleted_at = now(),
            deleted_vault_revision = $3,
            updated_at = now()
        WHERE id = $1 AND vault_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(input.item_id)
    .bind(input.vault_id)
    .bind(vault_revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected != 1 {
        return Err(StorageError::NotFound);
    }

    tx.commit().await?;
    Ok(DeletedItemRecord {
        item_id: input.item_id,
        vault_id: input.vault_id,
        deleted_vault_revision: vault_revision,
    })
}

pub async fn list_deleted_item_ids_since(
    &self,
    vault_id: VaultId,
    since_vault_revision: RevisionId,
) -> Result<Vec<DeletedItemRecord>, StorageError> {
    let rows = sqlx::query(
        r#"
        SELECT id, vault_id, deleted_vault_revision
        FROM items
        WHERE vault_id = $1
          AND deleted_vault_revision IS NOT NULL
          AND deleted_vault_revision > $2
        ORDER BY deleted_vault_revision ASC, id ASC
        "#,
    )
    .bind(vault_id)
    .bind(since_vault_revision)
    .fetch_all(&self.pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(DeletedItemRecord {
                item_id: row.try_get("id")?,
                vault_id: row.try_get("vault_id")?,
                deleted_vault_revision: row.try_get("deleted_vault_revision")?,
            })
        })
        .collect()
}
```

Then change `list_item_revisions_since` query to exclude deleted items:

```rust
SELECT ir.id, ir.item_id, ir.vault_id, ir.revision, ir.vault_revision, ir.key_generation, ir.author_user_id, ir.envelope, ir.created_at
FROM item_revisions ir
INNER JOIN items i ON i.id = ir.item_id AND i.vault_id = ir.vault_id
WHERE ir.vault_id = $1
  AND ir.vault_revision > $2
  AND i.deleted_at IS NULL
ORDER BY ir.vault_revision ASC
```

- [ ] **Step 2: Implement SQLite soft delete**

In `crates/umbra-storage/src/sqlite/items.rs`, change the top import:

```rust
use umbra_core::{ItemId, RevisionId, VaultId};
```

Change the crate import to:

```rust
use crate::{
    CreateEncryptedItem, CreateItemRevision, DeleteItem, DeletedItemRecord, ItemRevisionRecord,
    StorageError,
};
```

Add these methods inside `impl SqliteStorage` after `create_item_revision`:

```rust
pub async fn delete_item(
    &self,
    input: DeleteItem,
) -> Result<DeletedItemRecord, StorageError> {
    let mut tx = self.pool.begin().await?;

    let current_revision: i64 = sqlx::query_scalar(
        "SELECT current_revision FROM items WHERE id = ?1 AND vault_id = ?2 AND deleted_at IS NULL",
    )
    .bind(input.item_id.to_string())
    .bind(input.vault_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(StorageError::NotFound)?;

    if current_revision != input.expected_revision {
        return Err(StorageError::Conflict);
    }

    let vault_revision: i64 = sqlx::query_scalar(
        "UPDATE vaults SET vault_revision = vault_revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 RETURNING vault_revision",
    )
    .bind(input.vault_id.to_string())
    .fetch_one(&mut *tx)
    .await?;

    let affected = sqlx::query(
        "UPDATE items SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), deleted_vault_revision = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 AND vault_id = ?2 AND deleted_at IS NULL",
    )
    .bind(input.item_id.to_string())
    .bind(input.vault_id.to_string())
    .bind(vault_revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected != 1 {
        return Err(StorageError::NotFound);
    }

    tx.commit().await?;
    Ok(DeletedItemRecord {
        item_id: input.item_id,
        vault_id: input.vault_id,
        deleted_vault_revision: vault_revision,
    })
}

pub async fn list_deleted_item_ids_since(
    &self,
    vault_id: VaultId,
    since_vault_revision: RevisionId,
) -> Result<Vec<DeletedItemRecord>, StorageError> {
    let rows = sqlx::query(
        r#"
        SELECT id, vault_id, deleted_vault_revision
        FROM items
        WHERE vault_id = ?1
          AND deleted_vault_revision IS NOT NULL
          AND deleted_vault_revision > ?2
        ORDER BY deleted_vault_revision ASC, id ASC
        "#,
    )
    .bind(vault_id.to_string())
    .bind(since_vault_revision)
    .fetch_all(&self.pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(DeletedItemRecord {
                item_id: crate::sqlite::convert::parse_uuid(row.try_get::<_, String>("id")?)?,
                vault_id: crate::sqlite::convert::parse_uuid(row.try_get::<_, String>("vault_id")?)?,
                deleted_vault_revision: row.try_get("deleted_vault_revision")?,
            })
        })
        .collect()
}
```

Then change `list_item_revisions_since` query to exclude deleted items:

```rust
SELECT ir.id, ir.item_id, ir.vault_id, ir.revision, ir.vault_revision, ir.key_generation, ir.author_user_id, ir.envelope, ir.created_at
FROM item_revisions ir
INNER JOIN items i ON i.id = ir.item_id AND i.vault_id = ir.vault_id
WHERE ir.vault_id = ?1
  AND ir.vault_revision > ?2
  AND i.deleted_at IS NULL
ORDER BY ir.vault_revision ASC
```

- [ ] **Step 3: Run storage check**

Run:

```bash
cargo check -p umbra-storage
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-storage/src/models.rs crates/umbra-storage/src/backend.rs crates/umbra-storage/src/postgres/items.rs crates/umbra-storage/src/sqlite/items.rs
git commit -m "feat(storage): soft delete vault items"
```

---

## Task 5: Storage Tests For Item Deletion

**Files:**
- Modify: `crates/umbra-storage/src/tests.rs`

- [ ] **Step 1: Add backend helper test function**

In `crates/umbra-storage/src/tests.rs`, add this helper near the existing shared helper functions:

```rust
async fn item_deletion_flow_on<S: StorageBackend + ?Sized>(storage: &S) {
    let owner = create_test_user_on(storage, "delete-owner@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Delete Vault".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(owner.id),
            crypto_policy: serde_json::json!({"min_envelope_version": 1}),
        })
        .await
        .unwrap();
    storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id: owner.id,
            role: VaultRole::Owner,
            state: MemberState::Active,
        })
        .await
        .unwrap();

    let created = storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id: vault.id,
            kind: ItemKind::Login,
            author_user_id: Some(owner.id),
            envelope: serde_json::json!({"ciphertext": "v1"}),
        })
        .await
        .unwrap();

    let deleted = storage
        .delete_item(DeleteItem {
            item_id: created.item_id,
            vault_id: vault.id,
            expected_revision: created.revision,
            author_user_id: Some(owner.id),
        })
        .await
        .unwrap();

    assert_eq!(deleted.item_id, created.item_id);
    assert_eq!(deleted.vault_id, vault.id);
    assert!(deleted.deleted_vault_revision > created.vault_revision);

    let deleted_since_create = storage
        .list_deleted_item_ids_since(vault.id, created.vault_revision)
        .await
        .unwrap();
    assert_eq!(deleted_since_create.len(), 1);
    assert_eq!(deleted_since_create[0].item_id, created.item_id);

    let active_revisions = storage.list_item_revisions_since(vault.id, 0).await.unwrap();
    assert!(active_revisions.is_empty());

    let stale_delete = storage
        .delete_item(DeleteItem {
            item_id: created.item_id,
            vault_id: vault.id,
            expected_revision: created.revision,
            author_user_id: Some(owner.id),
        })
        .await;
    assert!(matches!(stale_delete, Err(StorageError::NotFound)));
}
```

- [ ] **Step 2: Call helper from SQLite test**

Add this test near other SQLite tests:

```rust
#[tokio::test]
async fn sqlite_item_deletion_flow() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    item_deletion_flow_on(&storage).await;
}
```

- [ ] **Step 3: Call helper from Postgres test**

Add this test near other Postgres tests:

```rust
#[tokio::test]
#[serial(postgres)]
async fn postgres_item_deletion_flow() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    item_deletion_flow_on(&storage).await;
}
```

- [ ] **Step 4: Run storage tests**

Run:

```bash
cargo test -p umbra-storage sqlite_item_deletion_flow
cargo test -p umbra-storage postgres_item_deletion_flow
```

Expected: PASS. Postgres may skip if `UMBRA_TEST_DATABASE_URL` is not configured.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-storage/src/tests.rs
git commit -m "test(storage): cover item deletion flow"
```

---

## Task 6: Server Delete Endpoint And Sync Deleted Items

**Files:**
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Add failing server test**

In `crates/umbra-server/src/tests.rs`, make sure these imports are available:

```rust
use umbra_core::{DeviceState, ItemKind, VaultKind, VaultRole};
use umbra_protocol::{
    DeleteItemRequest, SyncRequest, SyncResponse, VaultSyncCursor,
};
```

In `crates/umbra-server/src/tests.rs`, add this test near `owner_can_create_update_and_sync_item_revisions`:

```rust
#[tokio::test]
async fn owner_can_delete_item_and_sync_deleted_item_id() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let login = register_and_signed_login(
        app.clone(),
        "delete-item@example.com",
        b"delete item password",
        "delete-item",
    )
    .await;
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000501").unwrap();
    let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000502").unwrap();

    let (status, vault): (StatusCode, VaultResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        login.auth("delete-create-vault"),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: Some(vault_id),
            name: "Delete".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"owner": "wrapping"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, created): (StatusCode, ItemRevisionResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/items", vault.vault_id),
        login.auth("delete-create-item"),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id: Some(item_id),
            kind: ItemKind::Login,
            envelope: json!({"ciphertext": "v1"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _deleted): (StatusCode, serde_json::Value) = signed_json_request(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/vaults/{}/items/{}", vault.vault_id, item_id),
        login.auth("delete-item"),
        &DeleteItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id,
            expected_revision: created.revision,
        },
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, sync): (StatusCode, SyncResponse) = signed_json_request(
        app,
        Method::POST,
        "/api/v1/sync",
        login.auth("delete-sync"),
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id: login.device_id,
            vaults: vec![VaultSyncCursor {
                vault_id: vault.vault_id,
                since_vault_revision: created.vault_revision,
            }],
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync.vaults.len(), 1);
    assert!(sync.vaults[0].items.is_empty());
    assert_eq!(sync.vaults[0].deleted_items, vec![item_id]);
    assert!(sync.vaults[0].latest_vault_revision > created.vault_revision);
}
```

- [ ] **Step 2: Run server test to verify it fails**

Run:

```bash
cargo test -p umbra-server owner_can_delete_item_and_sync_deleted_item_id
```

Expected: FAIL because the route and storage calls are missing.

- [ ] **Step 3: Add route**

In `crates/umbra-server/src/http.rs`, change:

```rust
.route(
    "/api/v1/vaults/:vault_id/items/:item_id",
    put(update_item),
)
```

to:

```rust
.route(
    "/api/v1/vaults/:vault_id/items/:item_id",
    put(update_item).delete(delete_item),
)
```

- [ ] **Step 4: Add handler**

In `crates/umbra-server/src/http.rs`, add after `update_item`:

```rust
async fn delete_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, item_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<DeleteItemRequest>,
) -> Result<StatusCode, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.vault_id != vault_id || request.item_id != item_id {
        return Err(ServerError::BadRequest("item path mismatch"));
    }

    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    ensure_vault_writer(&state, vault_id, user_id).await?;

    state
        .storage
        .delete_item(umbra_storage::DeleteItem {
            item_id,
            vault_id,
            expected_revision: request.expected_revision,
            author_user_id: Some(user_id),
        })
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
```

Ensure `DeleteItemRequest` is imported from `umbra_protocol`.

- [ ] **Step 5: Populate sync deleted_items**

In `sync`, before `vaults.push(...)`, add:

```rust
let deleted_items = state
    .storage
    .list_deleted_item_ids_since(cursor.vault_id, cursor.since_vault_revision)
    .await?
    .into_iter()
    .map(|deleted| deleted.item_id)
    .collect();
```

Then change:

```rust
deleted_items: vec![],
```

to:

```rust
deleted_items,
```

- [ ] **Step 6: Run server test**

Run:

```bash
cargo test -p umbra-server owner_can_delete_item_and_sync_deleted_item_id
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): delete vault items"
```

---

## Task 7: CLI Cache Support For Deleted Items

**Files:**
- Modify: `crates/umbra-cli/src/cache.rs`

- [ ] **Step 1: Add failing cache test**

In `crates/umbra-cli/src/cache.rs`, add this test to the existing test module:

```rust
#[test]
fn apply_sync_changes_removes_deleted_items() {
    let temp = tempfile::tempdir().unwrap();
    let cache = open_cache_at(temp.path(), "delete-cache");
    let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000601").unwrap();
    let item_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000602").unwrap();

    cache
        .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
            vault_id,
            latest_vault_revision: 1,
            latest_access_revision: 1,
            items: vec![umbra_protocol::ItemRevisionResponse {
                item_id,
                vault_id,
                revision: 1,
                vault_revision: 1,
                key_generation: 1,
                author_user_id: None,
                envelope: serde_json::json!({"ciphertext": "encrypted"}),
            }],
            deleted_items: vec![],
            key_wrappings: vec![],
        })
        .unwrap();
    assert_eq!(cache.list_latest_item_revisions(vault_id).unwrap().len(), 1);

    cache
        .apply_sync_changes(&umbra_protocol::VaultSyncChanges {
            vault_id,
            latest_vault_revision: 2,
            latest_access_revision: 1,
            items: vec![],
            deleted_items: vec![item_id],
            key_wrappings: vec![],
        })
        .unwrap();

    assert!(cache.latest_item_revision(vault_id, item_id).unwrap().is_none());
    assert!(cache.list_latest_item_revisions(vault_id).unwrap().is_empty());
}
```

- [ ] **Step 2: Run cache test to verify it fails**

Run:

```bash
cargo test -p umbra-cli apply_sync_changes_removes_deleted_items
```

Expected: FAIL because `deleted_items` are ignored.

- [ ] **Step 3: Add direct cache helper**

In `impl LocalCache`, add after `upsert_item_revision`:

```rust
pub fn delete_item(&self, vault_id: uuid::Uuid, item_id: uuid::Uuid) -> Result<(), CliError> {
    self.connection.execute(
        "DELETE FROM item_revisions WHERE vault_id = ?1 AND item_id = ?2",
        params![vault_id.to_string(), item_id.to_string()],
    )?;
    Ok(())
}
```

- [ ] **Step 4: Apply synced deletions**

Inside `apply_sync_changes`, after the loop inserting `changes.items` and before key wrapping cleanup, add:

```rust
for item_id in &changes.deleted_items {
    tx.execute(
        "DELETE FROM item_revisions WHERE vault_id = ?1 AND item_id = ?2",
        params![changes.vault_id.to_string(), item_id.to_string()],
    )?;
}
```

- [ ] **Step 5: Run cache test**

Run:

```bash
cargo test -p umbra-cli apply_sync_changes_removes_deleted_items
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/cache.rs
git commit -m "feat(cli): remove deleted items from cache"
```

---

## Task 8: CLI HTTP DELETE With JSON Body

**Files:**
- Modify: `crates/umbra-cli/src/http.rs`

- [ ] **Step 1: Add method**

In `impl UmbraHttpClient`, add after `delete(&self, path: &str)`:

```rust
pub async fn delete_json<T>(&self, path: &str, body: &T) -> Result<(), CliError>
where
    T: serde::Serialize,
{
    self.send_empty(
        Method::DELETE,
        path,
        serde_json::to_vec(body).map_err(CliError::from)?,
    )
    .await
}
```

- [ ] **Step 2: Run CLI HTTP check**

Run:

```bash
cargo check -p umbra-cli
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/umbra-cli/src/http.rs
git commit -m "feat(cli): send json delete requests"
```

---

## Task 9: CLI Item Delete Command Surface

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add parser tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_item_delete_commands() {
    let vault_id = "00000000-0000-0000-0000-000000000701";
    let item_id = "00000000-0000-0000-0000-000000000702";

    let by_id = Cli::parse_from([
        "umbra",
        "item",
        "delete",
        "--vault-id",
        vault_id,
        "--item-id",
        item_id,
        "--yes",
    ]);
    assert!(matches!(
        by_id.command,
        Command::Item(ItemCommand::Delete {
            vault_id: Some(parsed_vault),
            vault: None,
            item_id: Some(parsed_item),
            title: None,
            yes: true,
        }) if parsed_vault.to_string() == vault_id && parsed_item.to_string() == item_id
    ));

    let by_title = Cli::parse_from([
        "umbra",
        "item",
        "delete",
        "--vault",
        "Personal",
        "--title",
        "GitHub",
    ]);
    assert!(matches!(
        by_title.command,
        Command::Item(ItemCommand::Delete {
            vault_id: None,
            vault: Some(vault),
            item_id: None,
            title: Some(title),
            yes: false,
        }) if vault == "Personal" && title == "GitHub"
    ));
}
```

- [ ] **Step 2: Run parser test to verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_item_delete_commands
```

Expected: FAIL because `ItemCommand::Delete` does not exist.

- [ ] **Step 3: Add enum variant**

In `crates/umbra-cli/src/main.rs`, add to `ItemCommand` after `Get` and before `Create`:

```rust
Delete {
    #[arg(long)]
    vault_id: Option<VaultId>,
    #[arg(long)]
    vault: Option<String>,
    #[arg(long)]
    item_id: Option<ItemId>,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    yes: bool,
},
```

- [ ] **Step 4: Run parser test**

Run:

```bash
cargo test -p umbra-cli parses_item_delete_commands
```

Expected: PASS after a temporary compile error in `commands.rs` is handled in Task 10. If the compiler reports non-exhaustive match on `ItemCommand::Delete`, continue directly to Task 10 before committing.

---

## Task 10: CLI Item Delete Implementation

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Import delete request**

In `crates/umbra-cli/src/commands.rs`, extend the `umbra_protocol` import with:

```rust
DeleteItemRequest,
```

- [ ] **Step 2: Add render helper**

Add near other render helpers:

```rust
fn render_item_deleted(
    output: OutputMode,
    vault_id: VaultId,
    item_id: ItemId,
    revision: RevisionId,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(&serde_json::json!({
            "deleted": true,
            "vault_id": vault_id,
            "item_id": item_id,
            "expected_revision": revision
        }));
    }
    crate::output::print_kv(&[
        ("deleted item", item_id.to_string()),
        ("vault_id", vault_id.to_string()),
        ("expected revision", revision.to_string()),
    ]);
    Ok(())
}
```

- [ ] **Step 3: Add command arm**

In `run`, add this arm before `Command::Item(ItemCommand::Create { ... })`:

```rust
Command::Item(ItemCommand::Delete {
    vault_id,
    vault,
    item_id,
    title,
    yes,
}) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id =
        resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        vault_id,
        crate::sync::SyncMode::IfChanged,
    )
    .await?;
    let selection = select_cached_item_revision_before_unlock_for_output(
        &cache,
        vault_id,
        item_id,
        title.as_deref(),
        output,
    )?;
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let revision = match selection {
        ItemSelectionNeed::Selected(revision) => revision,
        ItemSelectionNeed::NeedsTitleDecrypt => select_cached_item_revision_by_title(
            &cache,
            &vault_key,
            vault_id,
            title.as_deref().expect("title selector was validated"),
        )?,
        ItemSelectionNeed::NeedsInteractiveDecrypt => {
            select_cached_item_revision_interactively(&cache, &vault_key, vault_id)?
        }
    };

    if output.is_json() && !yes {
        return Err(CliError::Input("pass --yes to delete item in JSON mode"));
    }
    if !output.is_json()
        && !yes
        && !dialoguer::Confirm::new()
            .with_prompt("Delete this item?")
            .default(false)
            .interact()?
    {
        return Err(CliError::Input("item deletion cancelled"));
    }

    client
        .delete_json(
            &format!("/api/v1/vaults/{vault_id}/items/{}", revision.item_id),
            &DeleteItemRequest {
                protocol_version: PROTOCOL_VERSION,
                vault_id,
                item_id: revision.item_id,
                expected_revision: revision.revision,
            },
        )
        .await?;
    cache.delete_item(vault_id, revision.item_id)?;
    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        vault_id,
        crate::sync::SyncMode::Always,
    )
    .await?;
    render_item_deleted(output, vault_id, revision.item_id, revision.revision)
}
```

- [ ] **Step 4: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli parses_item_delete_commands
cargo check -p umbra-cli
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/tests.rs crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): delete vault items"
```

---

## Task 11: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol.md`

- [ ] **Step 1: Update README commands**

In `README.md`, near the item command examples, add:

````markdown
Delete an item by id or title:

```bash
umbra item delete --vault Personal --title GitHub
umbra item delete --vault-id <vault-id> --item-id <item-id> --yes
```

Deleting an item is a metadata operation on the server. The server marks the encrypted item as deleted, increments the vault revision, and future sync responses include the deleted item id so clients remove it from local encrypted cache.
````

- [ ] **Step 2: Update protocol docs**

In `docs/protocol.md`, after the item endpoint list, add:

```markdown
`DELETE /api/v1/vaults/:vault_id/items/:item_id` accepts `DeleteItemRequest` with `expected_revision`. The server checks writer permission and revision preconditions, then soft-deletes the item and increments the vault revision. Sync returns deleted item ids through `VaultSyncChanges.deleted_items`; item plaintext is never sent to or decrypted by the server.
```

- [ ] **Step 3: Run docs-adjacent checks**

Run:

```bash
cargo test -p umbra-cli parses_item_delete_commands
cargo test -p umbra-server owner_can_delete_item_and_sync_deleted_item_id
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/protocol.md
git commit -m "docs(cli): document item deletion"
```

---

## Task 12: Final Verification

**Files:**
- No source edits expected.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --all -- --check
```

Expected: PASS.

- [ ] **Step 2: Run workspace check**

Run:

```bash
cargo check --workspace
```

Expected: PASS.

- [ ] **Step 3: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 4: Inspect commits and status**

Run:

```bash
git log --oneline origin/main..HEAD
git status --short --branch
```

Expected commits include:

```txt
test(protocol): cover delete item request
feat(migrations): add item deletion revision
feat(storage): soft delete vault items
test(storage): cover item deletion flow
feat(server): delete vault items
feat(cli): remove deleted items from cache
feat(cli): send json delete requests
feat(cli): delete vault items
docs(cli): document item deletion
```

`git status` should show a clean worktree.

- [ ] **Step 5: Push main**

Run:

```bash
git push origin main
```

Expected: push succeeds.

---

## Self-Review

Spec coverage:

- Server item deletion exists and requires writer permission.
- Deletion is optimistic via `expected_revision`.
- Storage records deletion as metadata, not plaintext.
- Sync carries deleted item ids via the existing protocol field.
- CLI can delete by item id, title, or interactive selection.
- Local cache removes deleted item revisions.
- Migrations support syncable deletion revision for Postgres and SQLite.

Placeholder scan:

- The plan contains only concrete implementation instructions and no vague validation language.
- Each code-changing task includes exact file paths, code, commands, and expected outcomes.

Type consistency:

- `DeleteItem` and `DeletedItemRecord` are defined before storage trait methods use them.
- `DeleteItemRequest` already exists in protocol and is used by server and CLI.
- `deleted_items` already exists in `VaultSyncChanges` and is populated by server/cache tasks.
- CLI `ItemCommand::Delete` fields match parser tests and command implementation.
