# Vault Invite Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real zero-knowledge vault invite flow so an admin can invite an existing Umbra user by email and the invited user can list, accept, or reject the invite from the CLI.

**Architecture:** The inviting client resolves the recipient public key, unwraps the vault key locally, wraps that vault key for the recipient, and sends only the encrypted wrapping to the server. The server stores pending invite metadata plus the encrypted wrapping, and accepting an invite atomically activates vault membership and creates the stored wrapping without decrypting it.

**Tech Stack:** Rust, Clap, Axum, SQLx, PostgreSQL, SQLite, serde/serde_json, existing `umbra-protocol`, `umbra-storage`, `umbra-server`, and `umbra-cli`.

---

## Scope

Included:

- extend invite protocol types with encrypted vault-key wrapping and typed invite responses;
- add invite wrapping columns to Postgres and SQLite migrations;
- storage models and repository methods for create/list/accept/reject invite;
- server endpoints for create invite, list current-user invites, accept invite, and reject invite;
- CLI commands:
  - `umbra vault invite --vault Platform --email ana@example.com --role editor`;
  - `umbra invite list`;
  - `umbra invite accept <invite-id>`;
  - `umbra invite reject <invite-id>`;
- tests for protocol, migrations, storage, server, CLI parser, and docs.

Not included:

- SMTP/email delivery;
- inviting users without Umbra accounts;
- invite links or public tokens;
- browser/web UI;
- org-level invites;
- accepting an invite without a precomputed encrypted vault-key wrapping.

---

## File Structure

- Modify `crates/umbra-protocol/src/lib.rs`
  - Extend `InviteMemberRequest`.
  - Add `InviteResponse`, `PendingInviteResponse`, `RejectInviteRequest`.
  - Add serialization tests.

- Create `crates/umbra-migrations/migrations/000007_invite_wrappings.sql`
  - Add `vault_key_wrapping jsonb`, `accepted_user_id uuid`, and pending uniqueness for Postgres.

- Create `crates/umbra-migrations/sqlite/000007_invite_wrappings.sql`
  - Add `vault_key_wrapping text`, `accepted_user_id text`, and pending uniqueness for SQLite.

- Modify `crates/umbra-migrations/src/lib.rs`
  - Update migration count and version assertions.

- Modify `crates/umbra-storage/src/models.rs`
  - Add invite input and record structs.

- Modify `crates/umbra-storage/src/backend.rs`
  - Add invite methods to `StorageBackend` and backend impls.

- Create `crates/umbra-storage/src/postgres/invites.rs`
  - Implement Postgres invite persistence and accept/reject flows.

- Create `crates/umbra-storage/src/sqlite/invites.rs`
  - Implement SQLite invite persistence and accept/reject flows.

- Modify `crates/umbra-storage/src/postgres/mod.rs`
  - Register `invites` module.

- Modify `crates/umbra-storage/src/sqlite/mod.rs`
  - Register `invites` module.

- Modify `crates/umbra-storage/src/tests.rs`
  - Add shared storage tests for invite lifecycle.

- Modify `crates/umbra-server/src/http.rs`
  - Add invite routes and handlers.

- Modify `crates/umbra-server/src/tests.rs`
  - Add signed API tests for invite create/list/accept/reject.

- Modify `crates/umbra-cli/src/main.rs`
  - Add `InviteCommand` and `vault invite`.

- Modify `crates/umbra-cli/src/commands.rs`
  - Implement vault invite and invite list/accept/reject.

- Modify `crates/umbra-cli/src/tests.rs`
  - Add parser tests.

- Modify `README.md`, `docs/protocol.md`, and `docs/architecture.md`
  - Document invite CLI and protocol semantics.

---

## Task 1: Protocol Types For Invites

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`

- [ ] **Step 1: Extend invite request and add response structs**

Replace the current invite request structs:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub email: String,
    pub role: VaultRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub protocol_version: u16,
    pub invite_id: uuid::Uuid,
    pub device_id: DeviceId,
}
```

with:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub email: String,
    pub role: VaultRole,
    pub vault_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub protocol_version: u16,
    pub invite_id: uuid::Uuid,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectInviteRequest {
    pub protocol_version: u16,
    pub invite_id: uuid::Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResponse {
    pub invite_id: uuid::Uuid,
    pub vault_id: VaultId,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub role: VaultRole,
    pub state: String,
    pub invited_by: Option<UserId>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingInviteResponse {
    pub invite_id: uuid::Uuid,
    pub vault_id: VaultId,
    pub vault_name: String,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub role: VaultRole,
    pub invited_by: Option<UserId>,
    pub expires_at: Option<String>,
}
```

- [ ] **Step 2: Add protocol tests**

Inside the existing `#[cfg(test)] mod tests`, add:

```rust
#[test]
fn invite_member_request_carries_encrypted_wrapping() {
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000801").unwrap();
    let request = InviteMemberRequest {
        protocol_version: PROTOCOL_VERSION,
        vault_id,
        email: "ana@example.com".to_owned(),
        role: VaultRole::Editor,
        vault_key_wrapping: json!({"version": 1, "ciphertext": "wrapped-vault-key"}),
    };

    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["protocol_version"], json!(1));
    assert_eq!(encoded["vault_id"], json!(vault_id.to_string()));
    assert_eq!(encoded["email"], json!("ana@example.com"));
    assert_eq!(encoded["role"], json!("editor"));
    assert_eq!(
        encoded["vault_key_wrapping"],
        json!({"version": 1, "ciphertext": "wrapped-vault-key"})
    );

    let decoded: InviteMemberRequest = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn invite_responses_roundtrip() {
    let invite_id = Uuid::parse_str("00000000-0000-0000-0000-000000000811").unwrap();
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000812").unwrap();
    let invited_by = Uuid::parse_str("00000000-0000-0000-0000-000000000813").unwrap();
    let invite = InviteResponse {
        invite_id,
        vault_id,
        org_id: None,
        email: "ana@example.com".to_owned(),
        role: VaultRole::Viewer,
        state: "pending".to_owned(),
        invited_by: Some(invited_by),
        expires_at: Some("2026-07-12T00:00:00Z".to_owned()),
    };
    let pending = PendingInviteResponse {
        invite_id,
        vault_id,
        vault_name: "Platform".to_owned(),
        org_id: None,
        email: "ana@example.com".to_owned(),
        role: VaultRole::Viewer,
        invited_by: Some(invited_by),
        expires_at: Some("2026-07-12T00:00:00Z".to_owned()),
    };

    assert_eq!(
        serde_json::from_value::<InviteResponse>(serde_json::to_value(&invite).unwrap()).unwrap(),
        invite
    );
    assert_eq!(
        serde_json::from_value::<PendingInviteResponse>(
            serde_json::to_value(&pending).unwrap()
        )
        .unwrap(),
        pending
    );
}
```

- [ ] **Step 3: Run protocol tests**

Run:

```bash
cargo test -p umbra-protocol invite_member_request_carries_encrypted_wrapping
cargo test -p umbra-protocol invite_responses_roundtrip
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs
git commit -m "feat(protocol): add vault invite types"
```

---

## Task 2: Database Migrations For Invite Wrappings

**Files:**
- Create: `crates/umbra-migrations/migrations/000007_invite_wrappings.sql`
- Create: `crates/umbra-migrations/sqlite/000007_invite_wrappings.sql`
- Modify: `crates/umbra-migrations/src/lib.rs`

- [ ] **Step 1: Add Postgres migration**

Create `crates/umbra-migrations/migrations/000007_invite_wrappings.sql`:

```sql
ALTER TABLE invites
ADD COLUMN vault_key_wrapping jsonb;

ALTER TABLE invites
ADD COLUMN accepted_user_id uuid REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE invites
ADD CONSTRAINT invites_vault_key_wrapping_required_for_pending
CHECK (state <> 'pending' OR vault_key_wrapping IS NOT NULL);

CREATE UNIQUE INDEX invites_pending_vault_email_idx
ON invites(vault_id, lower(email))
WHERE state = 'pending';
```

- [ ] **Step 2: Add SQLite migration**

Create `crates/umbra-migrations/sqlite/000007_invite_wrappings.sql`:

```sql
ALTER TABLE invites
ADD COLUMN vault_key_wrapping text;

ALTER TABLE invites
ADD COLUMN accepted_user_id text REFERENCES users(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX invites_pending_vault_email_idx
ON invites(vault_id, lower(email))
WHERE state = 'pending';
```

- [ ] **Step 3: Update migration embed test**

In `crates/umbra-migrations/src/lib.rs`, update the existing test:

```rust
assert_eq!(migrations.len(), 7);
assert_eq!(sqlite_migrations.len(), 7);
assert!(migrations.iter().any(|migration| {
    migration.version == 7 && migration.description == "invite wrappings"
}));
assert!(sqlite_migrations.iter().any(|migration| {
    migration.version == 7 && migration.description == "invite wrappings"
}));
```

Keep the existing version 4, 5, and 6 assertions.

- [ ] **Step 4: Run migration test**

Run:

```bash
cargo test -p umbra-migrations embeds_postgres_and_sqlite_migrations
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-migrations/src/lib.rs crates/umbra-migrations/migrations/000007_invite_wrappings.sql crates/umbra-migrations/sqlite/000007_invite_wrappings.sql
git commit -m "feat(migrations): add invite wrappings"
```

---

## Task 3: Storage Invite Models And Trait

**Files:**
- Modify: `crates/umbra-storage/src/models.rs`
- Modify: `crates/umbra-storage/src/backend.rs`

- [ ] **Step 1: Add storage models**

In `crates/umbra-storage/src/models.rs`, after `VaultMemberRecord`, add:

```rust
#[derive(Debug, Clone)]
pub struct CreateVaultInvite {
    pub id: Option<Uuid>,
    pub vault_id: VaultId,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub role: VaultRole,
    pub invited_by: Option<UserId>,
    pub vault_key_wrapping: Value,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct VaultInviteRecord {
    pub id: Uuid,
    pub vault_id: VaultId,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub role: VaultRole,
    pub state: String,
    pub invited_by: Option<UserId>,
    pub accepted_user_id: Option<UserId>,
    pub vault_key_wrapping: Value,
    pub created_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct PendingVaultInviteRecord {
    pub id: Uuid,
    pub vault_id: VaultId,
    pub vault_name: String,
    pub org_id: Option<OrgId>,
    pub email: String,
    pub role: VaultRole,
    pub invited_by: Option<UserId>,
    pub vault_key_wrapping: Value,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct AcceptVaultInvite {
    pub invite_id: Uuid,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
}
```

- [ ] **Step 2: Add trait methods**

In `crates/umbra-storage/src/backend.rs`, extend the `use crate::{ ... }` list with:

```rust
AcceptVaultInvite, CreateVaultInvite, PendingVaultInviteRecord, VaultInviteRecord,
```

Add these methods after `list_vault_members` in the `StorageBackend` trait:

```rust
async fn create_vault_invite(
    &self,
    input: CreateVaultInvite,
) -> Result<VaultInviteRecord, StorageError>;
async fn list_pending_vault_invites_for_email(
    &self,
    email: &str,
) -> Result<Vec<PendingVaultInviteRecord>, StorageError>;
async fn accept_vault_invite(
    &self,
    input: AcceptVaultInvite,
) -> Result<VaultMemberRecord, StorageError>;
async fn reject_vault_invite(
    &self,
    invite_id: Uuid,
    user_id: UserId,
) -> Result<VaultInviteRecord, StorageError>;
```

Add matching forwarding methods to `impl StorageBackend for PostgresStorage`:

```rust
async fn create_vault_invite(
    &self,
    input: CreateVaultInvite,
) -> Result<VaultInviteRecord, StorageError> {
    PostgresStorage::create_vault_invite(self, input).await
}

async fn list_pending_vault_invites_for_email(
    &self,
    email: &str,
) -> Result<Vec<PendingVaultInviteRecord>, StorageError> {
    PostgresStorage::list_pending_vault_invites_for_email(self, email).await
}

async fn accept_vault_invite(
    &self,
    input: AcceptVaultInvite,
) -> Result<VaultMemberRecord, StorageError> {
    PostgresStorage::accept_vault_invite(self, input).await
}

async fn reject_vault_invite(
    &self,
    invite_id: Uuid,
    user_id: UserId,
) -> Result<VaultInviteRecord, StorageError> {
    PostgresStorage::reject_vault_invite(self, invite_id, user_id).await
}
```

Add matching forwarding methods to `impl StorageBackend for crate::sqlite::SqliteStorage`:

```rust
async fn create_vault_invite(
    &self,
    input: CreateVaultInvite,
) -> Result<VaultInviteRecord, StorageError> {
    crate::sqlite::SqliteStorage::create_vault_invite(self, input).await
}

async fn list_pending_vault_invites_for_email(
    &self,
    email: &str,
) -> Result<Vec<PendingVaultInviteRecord>, StorageError> {
    crate::sqlite::SqliteStorage::list_pending_vault_invites_for_email(self, email).await
}

async fn accept_vault_invite(
    &self,
    input: AcceptVaultInvite,
) -> Result<VaultMemberRecord, StorageError> {
    crate::sqlite::SqliteStorage::accept_vault_invite(self, input).await
}

async fn reject_vault_invite(
    &self,
    invite_id: Uuid,
    user_id: UserId,
) -> Result<VaultInviteRecord, StorageError> {
    crate::sqlite::SqliteStorage::reject_vault_invite(self, invite_id, user_id).await
}
```

- [ ] **Step 3: Run storage check**

Run:

```bash
cargo check -p umbra-storage
```

Expected: FAIL because backend invite methods are declared but not implemented.

- [ ] **Step 4: Continue without committing**

Do not commit while `cargo check` fails. Continue directly to Task 4.

---

## Task 4: Postgres And SQLite Invite Storage

**Files:**
- Create: `crates/umbra-storage/src/postgres/invites.rs`
- Create: `crates/umbra-storage/src/sqlite/invites.rs`
- Modify: `crates/umbra-storage/src/postgres/mod.rs`
- Modify: `crates/umbra-storage/src/sqlite/mod.rs`

- [ ] **Step 1: Register modules**

In `crates/umbra-storage/src/postgres/mod.rs`, add:

```rust
mod invites;
```

In `crates/umbra-storage/src/sqlite/mod.rs`, add:

```rust
mod invites;
```

- [ ] **Step 2: Create Postgres implementation**

Create `crates/umbra-storage/src/postgres/invites.rs`:

```rust
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::convert::{str_to_vault_role, vault_member_from_row, vault_role_to_str};
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::{PostgresStorage, StorageError};

impl PostgresStorage {
    pub async fn create_vault_invite(
        &self,
        input: CreateVaultInvite,
    ) -> Result<VaultInviteRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO invites (
                id, vault_id, org_id, email, role, state, invited_by,
                vault_key_wrapping, expires_at
            )
            VALUES ($1, $2, $3, lower($4), $5, 'pending', $6, $7, $8)
            RETURNING id, vault_id, org_id, email, role, state, invited_by,
                      accepted_user_id, vault_key_wrapping, created_at, accepted_at, expires_at
            "#,
        )
        .bind(id)
        .bind(input.vault_id)
        .bind(input.org_id)
        .bind(input.email)
        .bind(vault_role_to_str(input.role))
        .bind(input.invited_by)
        .bind(input.vault_key_wrapping)
        .bind(input.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_invite_from_row(row)
    }

    pub async fn list_pending_vault_invites_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<PendingVaultInviteRecord>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT i.id, i.vault_id, v.name AS vault_name, i.org_id, i.email, i.role,
                   i.invited_by, i.vault_key_wrapping, i.expires_at
            FROM invites i
            INNER JOIN vaults v ON v.id = i.vault_id AND v.deleted_at IS NULL
            WHERE i.email = lower($1)
              AND i.state = 'pending'
              AND (i.expires_at IS NULL OR i.expires_at > now())
            ORDER BY i.created_at ASC
            "#,
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(pending_vault_invite_from_row).collect()
    }

    pub async fn accept_vault_invite(
        &self,
        input: AcceptVaultInvite,
    ) -> Result<VaultMemberRecord, StorageError> {
        let mut tx = self.pool.begin().await?;

        let invite_row = sqlx::query(
            r#"
            SELECT i.id, i.vault_id, i.org_id, i.email, i.role, i.state, i.invited_by,
                   i.accepted_user_id, i.vault_key_wrapping, i.created_at, i.accepted_at, i.expires_at
            FROM invites i
            INNER JOIN users u ON lower(u.email) = i.email
            WHERE i.id = $1
              AND u.id = $2
              AND i.state = 'pending'
              AND (i.expires_at IS NULL OR i.expires_at > now())
            FOR UPDATE
            "#,
        )
        .bind(input.invite_id)
        .bind(input.user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;
        let invite = vault_invite_from_row(invite_row)?;

        sqlx::query(
            "UPDATE invites SET state = 'accepted', accepted_user_id = $2, accepted_at = now() WHERE id = $1",
        )
        .bind(input.invite_id)
        .bind(input.user_id)
        .execute(&mut *tx)
        .await?;

        let member_row = sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, state)
            VALUES ($1, $2, $3, 'active')
            ON CONFLICT (vault_id, user_id) DO UPDATE SET
                role = excluded.role,
                state = 'active',
                updated_at = now()
            RETURNING vault_id, user_id, role, state, created_at, updated_at
            "#,
        )
        .bind(invite.vault_id)
        .bind(input.user_id)
        .bind(vault_role_to_str(invite.role))
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO vault_key_wrappings (
                id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation
            )
            VALUES (
                $1, $2, $3, $4, 'user_public_key', $5,
                (SELECT current_key_generation FROM vaults WHERE id = $2)
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(invite.vault_id)
        .bind(input.user_id)
        .bind(input.device_id)
        .bind(invite.vault_key_wrapping)
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE vaults SET access_revision = access_revision + 1, updated_at = now() WHERE id = $1")
            .bind(invite.vault_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        vault_member_from_row(member_row)
    }

    pub async fn reject_vault_invite(
        &self,
        invite_id: Uuid,
        user_id: Uuid,
    ) -> Result<VaultInviteRecord, StorageError> {
        let row = sqlx::query(
            r#"
            UPDATE invites i
            SET state = 'rejected'
            FROM users u
            WHERE i.id = $1
              AND u.id = $2
              AND lower(u.email) = i.email
              AND i.state = 'pending'
            RETURNING i.id, i.vault_id, i.org_id, i.email, i.role, i.state, i.invited_by,
                      i.accepted_user_id, i.vault_key_wrapping, i.created_at, i.accepted_at, i.expires_at
            "#,
        )
        .bind(invite_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        vault_invite_from_row(row)
    }
}

fn vault_invite_from_row(row: sqlx::postgres::PgRow) -> Result<VaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    Ok(VaultInviteRecord {
        id: row.try_get("id")?,
        vault_id: row.try_get("vault_id")?,
        org_id: row.try_get("org_id")?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        state: row.try_get("state")?,
        invited_by: row.try_get("invited_by")?,
        accepted_user_id: row.try_get("accepted_user_id")?,
        vault_key_wrapping: row.try_get("vault_key_wrapping")?,
        created_at: row.try_get("created_at")?,
        accepted_at: row.try_get("accepted_at")?,
        expires_at: row.try_get::<Option<DateTime<Utc>>, _>("expires_at")?,
    })
}

fn pending_vault_invite_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<PendingVaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    Ok(PendingVaultInviteRecord {
        id: row.try_get("id")?,
        vault_id: row.try_get("vault_id")?,
        vault_name: row.try_get("vault_name")?,
        org_id: row.try_get("org_id")?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        invited_by: row.try_get("invited_by")?,
        vault_key_wrapping: row.try_get("vault_key_wrapping")?,
        expires_at: row.try_get("expires_at")?,
    })
}
```

- [ ] **Step 3: Create SQLite implementation**

Create `crates/umbra-storage/src/sqlite/invites.rs`:

```rust
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use crate::convert::{str_to_vault_role, vault_role_to_str};
use crate::error::map_sqlx_error;
use crate::models::*;
use crate::sqlite::SqliteStorage;
use crate::sqlite::convert::{optional_time, parse_time, parse_uuid, vault_member_from_row};
use crate::{StorageError, VaultMemberRecord};

impl SqliteStorage {
    pub async fn create_vault_invite(
        &self,
        input: CreateVaultInvite,
    ) -> Result<VaultInviteRecord, StorageError> {
        let id = input.id.unwrap_or_else(Uuid::new_v4);
        let row = sqlx::query(
            r#"
            INSERT INTO invites (
                id, vault_id, org_id, email, role, state, invited_by,
                vault_key_wrapping, expires_at
            )
            VALUES (?1, ?2, ?3, lower(?4), ?5, 'pending', ?6, ?7, ?8)
            RETURNING id, vault_id, org_id, email, role, state, invited_by,
                      accepted_user_id, vault_key_wrapping, created_at, accepted_at, expires_at
            "#,
        )
        .bind(id.to_string())
        .bind(input.vault_id.to_string())
        .bind(input.org_id.map(|id| id.to_string()))
        .bind(input.email)
        .bind(vault_role_to_str(input.role))
        .bind(input.invited_by.map(|id| id.to_string()))
        .bind(input.vault_key_wrapping.to_string())
        .bind(input.expires_at.map(|time| time.to_rfc3339()))
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        vault_invite_from_row(row)
    }

    pub async fn list_pending_vault_invites_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<PendingVaultInviteRecord>, StorageError> {
        let now = Utc::now().to_rfc3339();
        let rows = sqlx::query(
            r#"
            SELECT i.id, i.vault_id, v.name AS vault_name, i.org_id, i.email, i.role,
                   i.invited_by, i.vault_key_wrapping, i.expires_at
            FROM invites i
            INNER JOIN vaults v ON v.id = i.vault_id AND v.deleted_at IS NULL
            WHERE i.email = lower(?1)
              AND i.state = 'pending'
              AND (i.expires_at IS NULL OR i.expires_at > ?2)
            ORDER BY i.created_at ASC
            "#,
        )
        .bind(email)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(pending_vault_invite_from_row).collect()
    }

    pub async fn accept_vault_invite(
        &self,
        input: AcceptVaultInvite,
    ) -> Result<VaultMemberRecord, StorageError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now().to_rfc3339();

        let invite_row = sqlx::query(
            r#"
            SELECT i.id, i.vault_id, i.org_id, i.email, i.role, i.state, i.invited_by,
                   i.accepted_user_id, i.vault_key_wrapping, i.created_at, i.accepted_at, i.expires_at
            FROM invites i
            INNER JOIN users u ON lower(u.email) = i.email
            WHERE i.id = ?1
              AND u.id = ?2
              AND i.state = 'pending'
              AND (i.expires_at IS NULL OR i.expires_at > ?3)
            "#,
        )
        .bind(input.invite_id.to_string())
        .bind(input.user_id.to_string())
        .bind(&now)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::NotFound)?;
        let invite = vault_invite_from_row(invite_row)?;

        sqlx::query(
            "UPDATE invites SET state = 'accepted', accepted_user_id = ?2, accepted_at = ?3 WHERE id = ?1",
        )
        .bind(input.invite_id.to_string())
        .bind(input.user_id.to_string())
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        let member_row = sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, state)
            VALUES (?1, ?2, ?3, 'active')
            ON CONFLICT (vault_id, user_id) DO UPDATE SET
                role = excluded.role,
                state = 'active',
                updated_at = ?4
            RETURNING vault_id, user_id, role, state, created_at, updated_at
            "#,
        )
        .bind(invite.vault_id.to_string())
        .bind(input.user_id.to_string())
        .bind(vault_role_to_str(invite.role))
        .bind(&now)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO vault_key_wrappings (
                id, vault_id, user_id, device_id, wrapping_type, envelope, key_generation
            )
            VALUES (
                ?1, ?2, ?3, ?4, 'user_public_key', ?5,
                (SELECT current_key_generation FROM vaults WHERE id = ?2)
            )
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(invite.vault_id.to_string())
        .bind(input.user_id.to_string())
        .bind(input.device_id.map(|id| id.to_string()))
        .bind(invite.vault_key_wrapping.to_string())
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE vaults SET access_revision = access_revision + 1, updated_at = ?2 WHERE id = ?1")
            .bind(invite.vault_id.to_string())
            .bind(&now)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        vault_member_from_row(member_row)
    }

    pub async fn reject_vault_invite(
        &self,
        invite_id: Uuid,
        user_id: Uuid,
    ) -> Result<VaultInviteRecord, StorageError> {
        let row = sqlx::query(
            r#"
            UPDATE invites
            SET state = 'rejected'
            WHERE id = ?1
              AND state = 'pending'
              AND email = (SELECT lower(email) FROM users WHERE id = ?2)
            RETURNING id, vault_id, org_id, email, role, state, invited_by,
                      accepted_user_id, vault_key_wrapping, created_at, accepted_at, expires_at
            "#,
        )
        .bind(invite_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;

        vault_invite_from_row(row)
    }
}

fn vault_invite_from_row(row: sqlx::sqlite::SqliteRow) -> Result<VaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let wrapping: String = row.try_get("vault_key_wrapping")?;
    Ok(VaultInviteRecord {
        id: parse_uuid(row.try_get::<String, _>("id")?)?,
        vault_id: parse_uuid(row.try_get::<String, _>("vault_id")?)?,
        org_id: row
            .try_get::<Option<String>, _>("org_id")?
            .map(parse_uuid)
            .transpose()?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        state: row.try_get("state")?,
        invited_by: row
            .try_get::<Option<String>, _>("invited_by")?
            .map(parse_uuid)
            .transpose()?,
        accepted_user_id: row
            .try_get::<Option<String>, _>("accepted_user_id")?
            .map(parse_uuid)
            .transpose()?,
        vault_key_wrapping: serde_json::from_str(&wrapping)?,
        created_at: parse_time(row.try_get::<String, _>("created_at")?)?,
        accepted_at: optional_time(row.try_get("accepted_at")?)?,
        expires_at: optional_time(row.try_get("expires_at")?)?,
    })
}

fn pending_vault_invite_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<PendingVaultInviteRecord, StorageError> {
    let role: String = row.try_get("role")?;
    let wrapping: String = row.try_get("vault_key_wrapping")?;
    Ok(PendingVaultInviteRecord {
        id: parse_uuid(row.try_get::<String, _>("id")?)?,
        vault_id: parse_uuid(row.try_get::<String, _>("vault_id")?)?,
        vault_name: row.try_get("vault_name")?,
        org_id: row
            .try_get::<Option<String>, _>("org_id")?
            .map(parse_uuid)
            .transpose()?,
        email: row.try_get("email")?,
        role: str_to_vault_role(&role)?,
        invited_by: row
            .try_get::<Option<String>, _>("invited_by")?
            .map(parse_uuid)
            .transpose()?,
        vault_key_wrapping: serde_json::from_str(&wrapping)?,
        expires_at: optional_time(row.try_get("expires_at")?)?,
    })
}
```

- [ ] **Step 4: Run storage check**

Run:

```bash
cargo check -p umbra-storage
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-storage/src/models.rs crates/umbra-storage/src/backend.rs crates/umbra-storage/src/postgres/invites.rs crates/umbra-storage/src/sqlite/invites.rs crates/umbra-storage/src/postgres/mod.rs crates/umbra-storage/src/sqlite/mod.rs
git commit -m "feat(storage): add vault invite lifecycle"
```

---

## Task 5: Storage Tests For Invite Lifecycle

**Files:**
- Modify: `crates/umbra-storage/src/tests.rs`

- [ ] **Step 1: Add shared helper test**

In `crates/umbra-storage/src/tests.rs`, add this helper near the existing shared helper functions:

```rust
async fn vault_invite_lifecycle_on<S: StorageBackend + ?Sized>(storage: &S) {
    let owner = create_test_user_on(storage, "invite-owner@example.com").await;
    let recipient = create_test_user_on(storage, "invite-recipient@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Invite Vault".to_owned(),
            kind: VaultKind::Shared,
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

    let invite = storage
        .create_vault_invite(CreateVaultInvite {
            id: None,
            vault_id: vault.id,
            org_id: None,
            email: "INVITE-RECIPIENT@example.com".to_owned(),
            role: VaultRole::Editor,
            invited_by: Some(owner.id),
            vault_key_wrapping: serde_json::json!({"wrapped": "vault-key"}),
            expires_at: None,
        })
        .await
        .unwrap();

    assert_eq!(invite.vault_id, vault.id);
    assert_eq!(invite.email, "invite-recipient@example.com");
    assert_eq!(invite.role, VaultRole::Editor);
    assert_eq!(invite.state, "pending");

    let pending = storage
        .list_pending_vault_invites_for_email("invite-recipient@example.com")
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, invite.id);
    assert_eq!(pending[0].vault_name, "Invite Vault");

    let member = storage
        .accept_vault_invite(AcceptVaultInvite {
            invite_id: invite.id,
            user_id: recipient.id,
            device_id: None,
        })
        .await
        .unwrap();
    assert_eq!(member.vault_id, vault.id);
    assert_eq!(member.user_id, recipient.id);
    assert_eq!(member.role, VaultRole::Editor);
    assert_eq!(member.state, MemberState::Active);

    let wrappings = storage
        .list_key_wrappings_for_user_vault(recipient.id, vault.id)
        .await
        .unwrap();
    assert_eq!(wrappings.len(), 1);
    assert_eq!(wrappings[0].envelope, serde_json::json!({"wrapped": "vault-key"}));

    let pending_after_accept = storage
        .list_pending_vault_invites_for_email("invite-recipient@example.com")
        .await
        .unwrap();
    assert!(pending_after_accept.is_empty());

    let second_accept = storage
        .accept_vault_invite(AcceptVaultInvite {
            invite_id: invite.id,
            user_id: recipient.id,
            device_id: None,
        })
        .await;
    assert!(matches!(second_accept, Err(StorageError::NotFound)));
}
```

- [ ] **Step 2: Add SQLite test**

Add near other SQLite tests:

```rust
#[tokio::test]
async fn sqlite_vault_invite_lifecycle() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    vault_invite_lifecycle_on(&storage).await;
}
```

- [ ] **Step 3: Add Postgres test**

Add near other Postgres tests:

```rust
#[tokio::test]
#[serial(postgres)]
async fn postgres_vault_invite_lifecycle() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };

    vault_invite_lifecycle_on(&storage).await;
}
```

- [ ] **Step 4: Run storage tests**

Run:

```bash
cargo test -p umbra-storage sqlite_vault_invite_lifecycle
cargo test -p umbra-storage postgres_vault_invite_lifecycle
```

Expected: PASS. Postgres can skip when `UMBRA_TEST_DATABASE_URL` is not configured.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-storage/src/tests.rs
git commit -m "test(storage): cover vault invite lifecycle"
```

---

## Task 6: Server Invite API

**Files:**
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Add server routes**

In `router`, add these protected routes near the existing vault member routes:

```rust
.route("/api/v1/invites", get(list_my_invites))
.route(
    "/api/v1/vaults/:vault_id/invites",
    post(create_vault_invite),
)
.route("/api/v1/invites/:invite_id/accept", post(accept_invite))
.route("/api/v1/invites/:invite_id/reject", post(reject_invite))
```

- [ ] **Step 2: Add protocol and storage imports**

In the `umbra_protocol` import list, add:

```rust
AcceptInviteRequest, InviteMemberRequest, InviteResponse, PendingInviteResponse,
RejectInviteRequest,
```

In the `umbra_storage` import list, add:

```rust
AcceptVaultInvite, CreateVaultInvite,
```

- [ ] **Step 3: Add response mapping helpers**

Near existing response helpers, add:

```rust
fn invite_response(invite: umbra_storage::VaultInviteRecord) -> InviteResponse {
    InviteResponse {
        invite_id: invite.id,
        vault_id: invite.vault_id,
        org_id: invite.org_id,
        email: invite.email,
        role: invite.role,
        state: invite.state,
        invited_by: invite.invited_by,
        expires_at: invite.expires_at.map(|time| time.to_rfc3339()),
    }
}

fn pending_invite_response(
    invite: umbra_storage::PendingVaultInviteRecord,
) -> PendingInviteResponse {
    PendingInviteResponse {
        invite_id: invite.id,
        vault_id: invite.vault_id,
        vault_name: invite.vault_name,
        org_id: invite.org_id,
        email: invite.email,
        role: invite.role,
        invited_by: invite.invited_by,
        expires_at: invite.expires_at.map(|time| time.to_rfc3339()),
    }
}
```

- [ ] **Step 4: Add handlers**

Add after `add_vault_member`:

```rust
async fn create_vault_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(request): Json<InviteMemberRequest>,
) -> Result<Json<InviteResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.vault_id != vault_id {
        return Err(ServerError::BadRequest("vault id mismatch"));
    }

    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    ensure_vault_admin(&state, vault_id, user_id).await?;
    let vault = state.storage.find_vault_by_id(vault_id).await?;

    let invite = state
        .storage
        .create_vault_invite(CreateVaultInvite {
            id: None,
            vault_id,
            org_id: vault.org_id,
            email: request.email,
            role: request.role,
            invited_by: Some(user_id),
            vault_key_wrapping: request.vault_key_wrapping,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::days(7)),
        })
        .await?;

    Ok(Json(invite_response(invite)))
}

async fn list_my_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PendingInviteResponse>>, ServerError> {
    let context = authenticate_trusted_context(&state, &headers).await?;
    let user = state.storage.find_user_by_id(context.user_id).await?;
    let invites = state
        .storage
        .list_pending_vault_invites_for_email(&user.email)
        .await?;
    Ok(Json(invites.into_iter().map(pending_invite_response).collect()))
}

async fn accept_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(invite_id): Path<Uuid>,
    Json(request): Json<AcceptInviteRequest>,
) -> Result<Json<VaultMemberResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.invite_id != invite_id {
        return Err(ServerError::BadRequest("invite id mismatch"));
    }

    let context = authenticate_trusted_context(&state, &headers).await?;
    if context.device_id != Some(request.device_id) {
        return Err(ServerError::BadRequest("device id mismatch"));
    }
    let member = state
        .storage
        .accept_vault_invite(AcceptVaultInvite {
            invite_id,
            user_id: context.user_id,
            device_id: None,
        })
        .await?;

    Ok(Json(vault_member_response(member)))
}

async fn reject_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(invite_id): Path<Uuid>,
    Json(request): Json<RejectInviteRequest>,
) -> Result<Json<InviteResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.invite_id != invite_id {
        return Err(ServerError::BadRequest("invite id mismatch"));
    }

    let context = authenticate_trusted_context(&state, &headers).await?;
    let invite = state
        .storage
        .reject_vault_invite(invite_id, context.user_id)
        .await?;

    Ok(Json(invite_response(invite)))
}
```

- [ ] **Step 5: Add server tests**

In `crates/umbra-server/src/tests.rs`, add a signed test near vault member tests:

```rust
#[tokio::test]
#[serial(postgres)]
async fn invited_user_can_list_accept_and_sync_vault() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let owner = register_and_signed_login(
        app.clone(),
        "invite-owner@example.com",
        b"invite owner password",
        "invite-owner",
    )
    .await;
    let recipient = register_and_signed_login(
        app.clone(),
        "invite-recipient@example.com",
        b"invite recipient password",
        "invite-recipient",
    )
    .await;

    let (_status, vault): (StatusCode, VaultResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        owner.auth("invite-create-vault"),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Invite Vault".to_owned(),
            kind: VaultKind::Shared,
            initial_key_wrapping: json!({"owner": "wrapping"}),
        },
    )
    .await;

    let (status, invite): (StatusCode, InviteResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/invites", vault.vault_id),
        owner.auth("invite-create"),
        &InviteMemberRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            email: "INVITE-RECIPIENT@example.com".to_owned(),
            role: VaultRole::Editor,
            vault_key_wrapping: json!({"wrapped": "for-recipient"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(invite.email, "invite-recipient@example.com");
    assert_eq!(invite.state, "pending");

    let (status, invites): (StatusCode, Vec<PendingInviteResponse>) = signed_json_request(
        app.clone(),
        Method::GET,
        "/api/v1/invites",
        recipient.auth("invite-list"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].invite_id, invite.invite_id);
    assert_eq!(invites[0].vault_name, "Invite Vault");

    let (status, member): (StatusCode, VaultMemberResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/invites/{}/accept", invite.invite_id),
        recipient.auth("invite-accept"),
        &AcceptInviteRequest {
            protocol_version: PROTOCOL_VERSION,
            invite_id: invite.invite_id,
            device_id: recipient.device_id,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(member.vault_id, vault.vault_id);
    assert_eq!(member.user_id, recipient.user_id);
    assert_eq!(member.role, VaultRole::Editor);

    let (status, sync): (StatusCode, SyncResponse) = signed_json_request(
        app,
        Method::POST,
        "/api/v1/sync",
        recipient.auth("invite-sync"),
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id: recipient.device_id,
            vaults: vec![VaultSyncCursor {
                vault_id: vault.vault_id,
                since_vault_revision: 0,
            }],
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync.vaults.len(), 1);
    assert_eq!(sync.vaults[0].key_wrappings.len(), 1);
    assert_eq!(
        sync.vaults[0].key_wrappings[0].envelope,
        json!({"wrapped": "for-recipient"})
    );
}
```

Add a reject test:

```rust
#[tokio::test]
#[serial(postgres)]
async fn invited_user_can_reject_invite() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let owner = register_and_signed_login(
        app.clone(),
        "reject-owner@example.com",
        b"reject owner password",
        "reject-owner",
    )
    .await;
    let recipient = register_and_signed_login(
        app.clone(),
        "reject-recipient@example.com",
        b"reject recipient password",
        "reject-recipient",
    )
    .await;

    let (_status, vault): (StatusCode, VaultResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        owner.auth("reject-create-vault"),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: None,
            name: "Reject Vault".to_owned(),
            kind: VaultKind::Shared,
            initial_key_wrapping: json!({"owner": "wrapping"}),
        },
    )
    .await;

    let (_status, invite): (StatusCode, InviteResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/invites", vault.vault_id),
        owner.auth("reject-create"),
        &InviteMemberRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            email: "reject-recipient@example.com".to_owned(),
            role: VaultRole::Viewer,
            vault_key_wrapping: json!({"wrapped": "reject"}),
        },
    )
    .await;

    let (status, rejected): (StatusCode, InviteResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/invites/{}/reject", invite.invite_id),
        recipient.auth("reject-invite"),
        &RejectInviteRequest {
            protocol_version: PROTOCOL_VERSION,
            invite_id: invite.invite_id,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rejected.state, "rejected");

    let (status, invites): (StatusCode, Vec<PendingInviteResponse>) = signed_json_request(
        app,
        Method::GET,
        "/api/v1/invites",
        recipient.auth("reject-list"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(invites.is_empty());
}
```

- [ ] **Step 6: Run server tests**

Run:

```bash
cargo test -p umbra-server invited_user_can_list_accept_and_sync_vault
cargo test -p umbra-server invited_user_can_reject_invite
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): add vault invite endpoints"
```

---

## Task 7: CLI Invite Commands

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add command surface**

In `crates/umbra-cli/src/main.rs`, add `Invite(InviteCommand),` to the top-level `Command` enum after `Vault(VaultCommand),`.

Add this enum near `VaultCommand`:

```rust
#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    List,
    Accept {
        invite_id: uuid::Uuid,
    },
    Reject {
        invite_id: uuid::Uuid,
    },
}
```

In `VaultCommand`, add this variant before `AddMember`:

```rust
Invite {
    #[arg(long)]
    vault_id: Option<VaultId>,
    #[arg(long)]
    vault: Option<String>,
    #[arg(long)]
    email: String,
    #[arg(long, value_parser = parse_vault_role)]
    role: VaultRole,
},
```

- [ ] **Step 2: Add parser tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_vault_invite_and_invite_commands() {
    let invite = Cli::parse_from([
        "umbra",
        "vault",
        "invite",
        "--vault",
        "Platform",
        "--email",
        "ana@example.com",
        "--role",
        "editor",
    ]);
    assert!(matches!(
        invite.command,
        Command::Vault(VaultCommand::Invite {
            vault: Some(vault),
            email,
            role,
            ..
        }) if vault == "Platform" && email == "ana@example.com" && role == VaultRole::Editor
    ));

    let invite_id = "00000000-0000-0000-0000-000000000901";
    let accept = Cli::parse_from(["umbra", "invite", "accept", invite_id]);
    assert!(matches!(
        accept.command,
        Command::Invite(InviteCommand::Accept { invite_id: parsed }) if parsed.to_string() == invite_id
    ));

    let reject = Cli::parse_from(["umbra", "invite", "reject", invite_id]);
    assert!(matches!(
        reject.command,
        Command::Invite(InviteCommand::Reject { invite_id: parsed }) if parsed.to_string() == invite_id
    ));

    let list = Cli::parse_from(["umbra", "invite", "list"]);
    assert!(matches!(list.command, Command::Invite(InviteCommand::List)));
}
```

- [ ] **Step 3: Add imports in commands**

In `crates/umbra-cli/src/commands.rs`, extend protocol imports with:

```rust
AcceptInviteRequest, InviteMemberRequest, InviteResponse, PendingInviteResponse,
RejectInviteRequest,
```

Extend the local command import with:

```rust
InviteCommand,
```

- [ ] **Step 4: Add render helpers**

Near other render helpers, add:

```rust
fn render_invite_created(output: OutputMode, invite: &InviteResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(invite);
    }
    crate::output::print_kv(&[
        ("invite_id", invite.invite_id.to_string()),
        ("vault_id", invite.vault_id.to_string()),
        ("email", invite.email.clone()),
        ("role", vault_role_label(invite.role).to_owned()),
        ("state", invite.state.clone()),
    ]);
    Ok(())
}

fn render_pending_invites(
    output: OutputMode,
    invites: &[PendingInviteResponse],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(invites);
    }
    let rows = invites
        .iter()
        .map(|invite| {
            vec![
                invite.invite_id.to_string(),
                invite.vault_name.clone(),
                invite.vault_id.to_string(),
                vault_role_label(invite.role).to_owned(),
                invite
                    .expires_at
                    .clone()
                    .unwrap_or_else(|| "never".to_owned()),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["invite_id", "vault", "vault_id", "role", "expires"], &rows);
    Ok(())
}

fn render_invite_rejected(output: OutputMode, invite: &InviteResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(invite);
    }
    crate::output::print_kv(&[
        ("invite_id", invite.invite_id.to_string()),
        ("state", invite.state.clone()),
    ]);
    Ok(())
}
```

- [ ] **Step 5: Implement command branches**

In the main `run` match, add before `Command::Vault(VaultCommand::Members { ... })`:

```rust
Command::Vault(VaultCommand::Invite {
    vault_id,
    vault,
    email,
    role,
}) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id =
        resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
    let client = UmbraHttpClient::new(profile)?;
    let user = lookup_user_by_email(&client, &email).await?;
    let target_public_key = UserPublicKey::from_base64url(&user.public_key)?;
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let vault_key_wrapping = wrap_vault_key_for_member(&target_public_key, &vault_key, vault_id)?;
    let invite: InviteResponse = client
        .post(
            &format!("/api/v1/vaults/{vault_id}/invites"),
            &InviteMemberRequest {
                protocol_version: PROTOCOL_VERSION,
                vault_id,
                email,
                role,
                vault_key_wrapping,
            },
        )
        .await?;
    render_invite_created(output, &invite)
}
Command::Invite(InviteCommand::List) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let invites: Vec<PendingInviteResponse> = client.get("/api/v1/invites").await?;
    render_pending_invites(output, &invites)
}
Command::Invite(InviteCommand::Accept { invite_id }) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra login` first",
    ))?;
    let client = UmbraHttpClient::new(profile)?;
    let member: VaultMemberResponse = client
        .post(
            &format!("/api/v1/invites/{invite_id}/accept"),
            &AcceptInviteRequest {
                protocol_version: PROTOCOL_VERSION,
                invite_id,
                device_id,
            },
        )
        .await?;
    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        member.vault_id,
        crate::sync::SyncMode::Always,
    )
    .await?;
    render_vault_member_added(output, &member)
}
Command::Invite(InviteCommand::Reject { invite_id }) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let invite: InviteResponse = client
        .post(
            &format!("/api/v1/invites/{invite_id}/reject"),
            &RejectInviteRequest {
                protocol_version: PROTOCOL_VERSION,
                invite_id,
            },
        )
        .await?;
    render_invite_rejected(output, &invite)
}
```

- [ ] **Step 6: Run CLI checks**

Run:

```bash
cargo test -p umbra-cli parses_vault_invite_and_invite_commands
cargo check -p umbra-cli
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/tests.rs crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): add vault invite commands"
```

---

## Task 8: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol.md`
- Modify: `docs/architecture.md`

- [ ] **Step 1: Update README**

In the shared vault section, replace the direct-only invite explanation with:

````markdown
Invite an existing Umbra user to a vault:

```bash
umbra vault invite --vault Platform --email ana@example.com --role editor
```

The inviting CLI looks up Ana's account public key, unwraps the vault key locally, wraps it for Ana, and sends only the encrypted wrapping plus invite metadata to the server.

Ana can then run:

```bash
umbra invite list
umbra invite accept <invite-id>
```

Accepting an invite creates Ana's vault membership and stores the encrypted vault-key wrapping. The server never receives the vault key in plaintext.
````

- [ ] **Step 2: Update protocol docs**

In `docs/protocol.md`, near the invite endpoint list, add:

```markdown
Vault invites are for existing Umbra accounts. `POST /api/v1/vaults/:vault_id/invites` accepts `InviteMemberRequest`, including `vault_key_wrapping`, which is produced client-side for the invited user's account public key. The server stores this encrypted wrapping without decrypting it.

`GET /api/v1/invites` lists pending invites for the authenticated user's email. `POST /api/v1/invites/:invite_id/accept` checks that the invite email matches the authenticated user, marks the invite accepted, creates active vault membership, and stores the encrypted vault-key wrapping for that user. `POST /api/v1/invites/:invite_id/reject` marks the invite rejected.
```

- [ ] **Step 3: Update architecture docs**

In `docs/architecture.md`, replace the sentence that says the first CLI sharing flow is direct membership with:

```markdown
The CLI supports two sharing flows. `vault add-member` remains an admin shortcut that immediately creates membership and a vault-key wrapping for an existing user. `vault invite` creates a pending invite containing only metadata and an encrypted vault-key wrapping for the invited user's account public key; `invite accept` activates membership and stores that wrapping without exposing vault-key plaintext to the server.
```

- [ ] **Step 4: Run docs-adjacent tests**

Run:

```bash
cargo test -p umbra-cli parses_vault_invite_and_invite_commands
cargo test -p umbra-server invited_user_can_list_accept_and_sync_vault
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/protocol.md docs/architecture.md
git commit -m "docs(vaults): document invite flow"
```

---

## Task 9: Final Verification

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
feat(protocol): add vault invite types
feat(migrations): add invite wrappings
feat(storage): add vault invite lifecycle
test(storage): cover vault invite lifecycle
feat(server): add vault invite endpoints
feat(cli): add vault invite commands
docs(vaults): document invite flow
```

`git status` should show a clean branch.

- [ ] **Step 5: Push main**

Run:

```bash
git push origin main
```

Expected: push succeeds.

---

## Self-Review

Spec coverage:

- Existing-user vault invites are covered by protocol, storage, server, CLI, and docs tasks.
- Zero-knowledge sharing is preserved because only the CLI creates `vault_key_wrapping`; server stores it as opaque JSON.
- Accepting an invite activates membership and stores the encrypted wrapping.
- Rejecting an invite removes it from the pending invite list.
- Postgres and SQLite receive matching schema and storage behavior.
- SMTP, invite links, users without accounts, and web UI are intentionally out of scope.

Placeholder scan:

- The plan uses concrete file paths, command names, request structs, response structs, SQL, and test bodies.
- The plan uses concrete validation rules and defines all new types before later tasks reference them.

Type consistency:

- `InviteMemberRequest.vault_key_wrapping` matches server and CLI usage.
- `AcceptInviteRequest.device_id` remains compatible with the existing protocol shape.
- `InviteResponse` and `PendingInviteResponse` are mapped from storage records without exposing encrypted wrapping in list responses.
- Storage accept flow returns `VaultMemberRecord`, which maps to existing `VaultMemberResponse`.
