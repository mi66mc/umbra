# Multi-Device Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add zero-knowledge multi-device trust so new devices can become trusted through approval from an existing trusted device or through password plus emergency kit recovery.

**Architecture:** Keep the first cut simple: account-level user private key remains the key that opens vault key wrappings, while each device has a signing key that authenticates HTTP requests. Unknown devices become `pending`, trusted devices can approve pending devices by uploading an encrypted bootstrap bundle, and recovery requires OPAQUE plus an account-key challenge decrypted with the recovered user private key. The server stores encrypted bootstrap bundles and device state only; it never sees user secret keys, private keys, vault keys, or plaintext items.

**Tech Stack:** Rust, Axum, SQLx/PostgreSQL migrations, OPAQUE, Ed25519 signed HTTP sessions, X25519/XChaCha20-Poly1305/HKDF in `umbra-crypto`, clap CLI, existing SQLite cache/config.

---

## Scope

This plan implements the approved design in `docs/superpowers/specs/2026-06-28-multi-device-trust-design.md`.

In scope:

- explicit `DeviceState`;
- device pending/trusted/revoked storage model;
- pending device OPAQUE login flow;
- trusted device approval flow;
- encrypted bootstrap bundle crypto;
- recovery trust with account-key encrypted challenge;
- device list/pending/approve/finish/recover/revoke CLI;
- server/storage/CLI/crypto tests.

Out of scope:

- per-device vault key wrappings;
- automatic vault key rotation on revoke;
- QR/deep-link approval UX;
- remote wipe of local cache.

## File Structure

- Modify `crates/umbra-core/src/lib.rs`
  - Add `DeviceState`.

- Modify `crates/umbra-protocol/src/lib.rs`
  - Add device DTOs for state, pending device creation, approval, bootstrap, recovery challenge, recovery trust, revoke, and responses.

- Create `crates/umbra-migrations/migrations/000005_device_trust_state.sql`
  - Add `devices.state`, pending approval fields, bootstrap fields, `trusted_at`.
  - Add recovery challenge table.

- Modify `crates/umbra-storage/src/models.rs`
  - Add `DeviceState` fields to device structs.
  - Add device pending/update/recovery structs.

- Modify `crates/umbra-storage/src/convert.rs`
  - Parse/serialize `DeviceState`.

- Modify `crates/umbra-storage/src/devices.rs`
  - Add pending device, approval, bootstrap, trust, revoke helpers.

- Modify `crates/umbra-storage/src/sessions.rs`
  - Add session revocation by device.

- Modify `crates/umbra-storage/src/tests.rs`
  - Add database coverage for state migration and device trust flow.

- Modify `crates/umbra-crypto/src/lib.rs`
  - Add bootstrap bundle encryption/decryption using X25519 recipient wrapping and AAD.
  - Add account recovery challenge encryption/decryption helpers.

- Modify `crates/umbra-server/src/authz.rs`
  - Return authenticated device context when available.
  - Enforce trusted device for protected resources.

- Modify `crates/umbra-server/src/signed_auth.rs`
  - Validate `DeviceState::Trusted` instead of `trusted`.

- Modify `crates/umbra-server/src/http.rs`
  - Add device routes.
  - Adjust OPAQUE login finish to create pending devices and limited sessions.

- Modify `crates/umbra-server/src/tests.rs`
  - Add HTTP integration tests for pending, approval, bootstrap, revoke, recovery.

- Modify `crates/umbra-cli/src/main.rs`
  - Add `DeviceCommand`.

- Modify `crates/umbra-cli/src/opaque.rs`
  - Send new device registration data during login and accept pending responses.

- Modify `crates/umbra-cli/src/commands.rs`
  - Add device command handlers and pending login behavior.

- Modify `crates/umbra-cli/src/config.rs`
  - Store pending bootstrap private key and pending approval code state.

- Modify `crates/umbra-cli/src/tests.rs`
  - Add clap parser tests for device commands.

- Modify `README.md` and `docs/protocol.md`
  - Document multi-device usage and protocol behavior.

---

### Task 1: Add Device State And Protocol DTOs

**Files:**
- Modify: `crates/umbra-core/src/lib.rs`
- Modify: `crates/umbra-protocol/src/lib.rs`

- [ ] **Step 1: Add `DeviceState` to core**

In `crates/umbra-core/src/lib.rs`, add after `MemberState`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Pending,
    Trusted,
    Revoked,
}

impl DeviceState {
    pub fn can_authenticate(self) -> bool {
        matches!(self, Self::Trusted)
    }

    pub fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}
```

Add this test in the existing `#[cfg(test)] mod tests`:

```rust
#[test]
fn serializes_device_state_as_snake_case() {
    let encoded = serde_json::to_string(&DeviceState::Pending).unwrap();
    assert_eq!(encoded, "\"pending\"");

    let decoded: DeviceState = serde_json::from_str("\"trusted\"").unwrap();
    assert_eq!(decoded, DeviceState::Trusted);
    assert!(decoded.can_authenticate());
}
```

- [ ] **Step 2: Add device protocol DTOs**

In `crates/umbra-protocol/src/lib.rs`, update the import:

```rust
use umbra_core::{
    DeviceId, DeviceState, ItemId, ItemKind, OrgId, OrgRole, RevisionId, UserId, VaultId,
    VaultKind, VaultRole,
};
```

Add these DTOs after `DeviceTrustRequest`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceResponse {
    pub device_id: DeviceId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub state: DeviceState,
    pub created_at: String,
    pub trusted_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceRequest {
    pub protocol_version: u16,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub bootstrap_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceResponse {
    pub device_id: DeviceId,
    pub session_id: uuid::Uuid,
    pub approval_code: String,
    pub fingerprint: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceSummary {
    pub device_id: DeviceId,
    pub name: String,
    pub fingerprint: String,
    pub bootstrap_public_key: String,
    pub approval_expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveDeviceRequest {
    pub protocol_version: u16,
    pub approval_code: String,
    pub bootstrap_bundle: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLookupRequest {
    pub protocol_version: u16,
    pub approval_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBootstrapResponse {
    pub device_id: DeviceId,
    pub state: DeviceState,
    pub bootstrap_bundle: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallengeStartRequest {
    pub protocol_version: u16,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallengeStartResponse {
    pub challenge_id: uuid::Uuid,
    pub encrypted_challenge: serde_json::Value,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverTrustRequest {
    pub protocol_version: u16,
    pub challenge_id: uuid::Uuid,
    pub challenge_response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverTrustResponse {
    pub device_id: DeviceId,
    pub state: DeviceState,
}
```

Extend `OpaqueLoginFinishRequest` to carry optional new-device material:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishRequest {
    pub protocol_version: u16,
    pub login_id: uuid::Uuid,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    #[serde(default)]
    pub pending_device: Option<PendingDeviceRequest>,
    pub credential_finalization: String,
}
```

Extend `OpaqueLoginFinishResponse`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishResponse {
    pub user_id: UserId,
    pub session_id: uuid::Uuid,
    pub session_token: Option<String>,
    pub auth_scheme: String,
    pub encrypted_private_key: serde_json::Value,
    #[serde(default)]
    pub pending_device: Option<PendingDeviceResponse>,
}
```

- [ ] **Step 3: Add protocol roundtrip tests**

Add this test to `crates/umbra-protocol/src/lib.rs` tests:

```rust
#[test]
fn pending_device_response_roundtrips() {
    let response = PendingDeviceResponse {
        device_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        session_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        approval_code: "UMBRA-7K4Q-2M9D".to_owned(),
        fingerprint: "SHA256:abc".to_owned(),
        expires_at: "2026-06-28T12:00:00Z".to_owned(),
    };

    let encoded = serde_json::to_string(&response).unwrap();
    let decoded: PendingDeviceResponse = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, response);
}
```

Add this test:

```rust
#[test]
fn opaque_login_finish_can_request_pending_device() {
    let request = OpaqueLoginFinishRequest {
        protocol_version: PROTOCOL_VERSION,
        login_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
        device_id: None,
        pending_device: Some(PendingDeviceRequest {
            protocol_version: PROTOCOL_VERSION,
            name: "new laptop".to_owned(),
            public_key: "device-public-key".to_owned(),
            fingerprint: "device-fingerprint".to_owned(),
            bootstrap_public_key: "bootstrap-public-key".to_owned(),
        }),
        credential_finalization: "final".to_owned(),
    };

    let value = serde_json::to_value(&request).unwrap();

    assert_eq!(value["pending_device"]["name"], serde_json::json!("new laptop"));
    assert_eq!(value["device_id"], serde_json::Value::Null);
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p umbra-core serializes_device_state_as_snake_case
cargo test -p umbra-protocol pending_device_response_roundtrips opaque_login_finish_can_request_pending_device
cargo test -p umbra-protocol
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-core/src/lib.rs crates/umbra-protocol/src/lib.rs
git commit -m "feat(protocol): add device trust contracts"
```

---

### Task 2: Add Device State Migration And Storage Model

**Files:**
- Create: `crates/umbra-migrations/migrations/000005_device_trust_state.sql`
- Modify: `crates/umbra-storage/src/models.rs`
- Modify: `crates/umbra-storage/src/convert.rs`
- Modify: `crates/umbra-storage/src/devices.rs`
- Modify: `crates/umbra-storage/src/sessions.rs`
- Modify: `crates/umbra-storage/src/tests.rs`

- [ ] **Step 1: Add migration**

Create `crates/umbra-migrations/migrations/000005_device_trust_state.sql`:

```sql
ALTER TABLE devices
    ADD COLUMN state text;

UPDATE devices
SET state = CASE
    WHEN revoked_at IS NOT NULL THEN 'revoked'
    WHEN trusted IS TRUE THEN 'trusted'
    ELSE 'pending'
END;

ALTER TABLE devices
    ALTER COLUMN state SET NOT NULL,
    ALTER COLUMN state SET DEFAULT 'pending',
    ADD CONSTRAINT devices_state_check CHECK (state IN ('pending', 'trusted', 'revoked')),
    ADD COLUMN approval_code_hash text,
    ADD COLUMN approval_expires_at timestamptz,
    ADD COLUMN bootstrap_public_key text,
    ADD COLUMN bootstrap_bundle jsonb,
    ADD COLUMN trusted_at timestamptz;

UPDATE devices
SET trusted_at = created_at
WHERE state = 'trusted' AND trusted_at IS NULL;

CREATE INDEX devices_user_state_idx ON devices(user_id, state);
CREATE INDEX devices_approval_code_hash_idx ON devices(approval_code_hash)
    WHERE approval_code_hash IS NOT NULL;

CREATE TABLE device_recovery_challenges (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    challenge_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX device_recovery_challenges_device_idx
    ON device_recovery_challenges(device_id, expires_at)
    WHERE consumed_at IS NULL;
```

- [ ] **Step 2: Update storage models**

In `crates/umbra-storage/src/models.rs`, update imports:

```rust
use umbra_core::{
    DeviceId, DeviceState, ItemId, ItemKind, MemberState, OrgId, OrgRole, RevisionId, UserId,
    VaultId, VaultKind, VaultRole,
};
```

Replace `CreateDevice` with:

```rust
#[derive(Debug, Clone)]
pub struct CreateDevice {
    pub id: Option<DeviceId>,
    pub user_id: UserId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub state: DeviceState,
    pub approval_code_hash: Option<String>,
    pub approval_expires_at: Option<DateTime<Utc>>,
    pub bootstrap_public_key: Option<String>,
}
```

Replace `DeviceRecord` with:

```rust
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub state: DeviceState,
    pub approval_code_hash: Option<String>,
    pub approval_expires_at: Option<DateTime<Utc>>,
    pub bootstrap_public_key: Option<String>,
    pub bootstrap_bundle: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub trusted_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}
```

Add these structs after `DeviceRecord`:

```rust
#[derive(Debug, Clone)]
pub struct ApprovePendingDevice {
    pub device_id: DeviceId,
    pub bootstrap_bundle: Value,
}

#[derive(Debug, Clone)]
pub struct CreateRecoveryChallenge {
    pub id: Option<Uuid>,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub challenge_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RecoveryChallengeRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub challenge_hash: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
```

- [ ] **Step 3: Update conversion helpers**

In `crates/umbra-storage/src/convert.rs`, update imports:

```rust
use umbra_core::{DeviceState, ItemKind, MemberState, OrgRole, VaultKind, VaultRole};
```

Replace `device_from_row`:

```rust
pub(crate) fn device_from_row(row: sqlx::postgres::PgRow) -> Result<DeviceRecord, StorageError> {
    let state: String = row.try_get("state")?;
    Ok(DeviceRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        name: row.try_get("name")?,
        public_key: row.try_get("public_key")?,
        fingerprint: row.try_get("fingerprint")?,
        state: str_to_device_state(&state)?,
        approval_code_hash: row.try_get("approval_code_hash")?,
        approval_expires_at: row.try_get("approval_expires_at")?,
        bootstrap_public_key: row.try_get("bootstrap_public_key")?,
        bootstrap_bundle: row.try_get("bootstrap_bundle")?,
        created_at: row.try_get("created_at")?,
        trusted_at: row.try_get("trusted_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}
```

Add near other string conversion helpers:

```rust
pub(crate) fn device_state_to_str(state: DeviceState) -> &'static str {
    match state {
        DeviceState::Pending => "pending",
        DeviceState::Trusted => "trusted",
        DeviceState::Revoked => "revoked",
    }
}

pub(crate) fn str_to_device_state(value: &str) -> Result<DeviceState, StorageError> {
    match value {
        "pending" => Ok(DeviceState::Pending),
        "trusted" => Ok(DeviceState::Trusted),
        "revoked" => Ok(DeviceState::Revoked),
        value => Err(StorageError::InvalidDatabaseValue {
            field: "devices.state",
            value: value.to_owned(),
        }),
    }
}
```

- [ ] **Step 4: Update device queries**

In `crates/umbra-storage/src/devices.rs`, define a reusable column list:

```rust
const DEVICE_COLUMNS: &str = "id, user_id, name, public_key, fingerprint, state, approval_code_hash, approval_expires_at, bootstrap_public_key, bootstrap_bundle, created_at, trusted_at, last_seen_at, revoked_at";
```

Update `create_device` query:

```rust
let row = sqlx::query(&format!(
    r#"
    INSERT INTO devices (
        id, user_id, name, public_key, fingerprint, trusted, state,
        approval_code_hash, approval_expires_at, bootstrap_public_key, trusted_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $7 = 'trusted' THEN now() ELSE NULL END)
    RETURNING {DEVICE_COLUMNS}
    "#
))
.bind(id)
.bind(input.user_id)
.bind(input.name)
.bind(input.public_key)
.bind(input.fingerprint)
.bind(matches!(input.state, DeviceState::Trusted))
.bind(device_state_to_str(input.state))
.bind(input.approval_code_hash)
.bind(input.approval_expires_at)
.bind(input.bootstrap_public_key)
.fetch_one(&self.pool)
.await
.map_err(map_sqlx_error)?;
```

Update `list_devices_for_user` query:

```rust
let rows = sqlx::query(&format!(
    r#"
    SELECT {DEVICE_COLUMNS}
    FROM devices
    WHERE user_id = $1
    ORDER BY created_at ASC
    "#
))
.bind(user_id)
.fetch_all(&self.pool)
.await?;
```

Update `find_device_by_id` query:

```rust
let row = sqlx::query(&format!(
    r#"
    SELECT {DEVICE_COLUMNS}
    FROM devices
    WHERE id = $1
    "#
))
.bind(device_id)
.fetch_optional(&self.pool)
.await?
.ok_or(StorageError::NotFound)?;
```

Add:

```rust
pub async fn list_pending_devices_for_user(
    &self,
    user_id: UserId,
) -> Result<Vec<DeviceRecord>, StorageError> {
    let rows = sqlx::query(&format!(
        r#"
        SELECT {DEVICE_COLUMNS}
        FROM devices
        WHERE user_id = $1 AND state = 'pending' AND revoked_at IS NULL
        ORDER BY created_at ASC
        "#
    ))
    .bind(user_id)
    .fetch_all(&self.pool)
    .await?;

    rows.into_iter().map(device_from_row).collect()
}

pub async fn find_pending_device_by_approval_hash(
    &self,
    user_id: UserId,
    approval_code_hash: &str,
) -> Result<DeviceRecord, StorageError> {
    let row = sqlx::query(&format!(
        r#"
        SELECT {DEVICE_COLUMNS}
        FROM devices
        WHERE user_id = $1
          AND approval_code_hash = $2
          AND state = 'pending'
          AND revoked_at IS NULL
          AND approval_expires_at > now()
        "#
    ))
    .bind(user_id)
    .bind(approval_code_hash)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StorageError::NotFound)?;

    device_from_row(row)
}

pub async fn approve_pending_device(
    &self,
    input: ApprovePendingDevice,
) -> Result<DeviceRecord, StorageError> {
    let row = sqlx::query(&format!(
        r#"
        UPDATE devices
        SET state = 'trusted',
            trusted = true,
            trusted_at = now(),
            bootstrap_bundle = $2,
            approval_code_hash = NULL,
            approval_expires_at = NULL
        WHERE id = $1
          AND state = 'pending'
          AND revoked_at IS NULL
          AND approval_expires_at > now()
        RETURNING {DEVICE_COLUMNS}
        "#
    ))
    .bind(input.device_id)
    .bind(input.bootstrap_bundle)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StorageError::NotFound)?;

    device_from_row(row)
}

pub async fn mark_device_trusted(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError> {
    let row = sqlx::query(&format!(
        r#"
        UPDATE devices
        SET state = 'trusted',
            trusted = true,
            trusted_at = now(),
            approval_code_hash = NULL,
            approval_expires_at = NULL
        WHERE id = $1 AND state = 'pending' AND revoked_at IS NULL
        RETURNING {DEVICE_COLUMNS}
        "#
    ))
    .bind(device_id)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StorageError::NotFound)?;

    device_from_row(row)
}
```

Update `revoke_device`:

```rust
pub async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError> {
    let result = sqlx::query(
        "UPDATE devices SET state = 'revoked', trusted = false, revoked_at = now() WHERE id = $1",
    )
    .bind(device_id)
    .execute(&self.pool)
    .await?;

    ensure_rows_affected(result.rows_affected())
}
```

- [ ] **Step 5: Add recovery challenge storage and session revoke**

In `crates/umbra-storage/src/devices.rs`, add:

```rust
pub async fn create_recovery_challenge(
    &self,
    input: CreateRecoveryChallenge,
) -> Result<RecoveryChallengeRecord, StorageError> {
    let id = input.id.unwrap_or_else(Uuid::new_v4);
    let row = sqlx::query(
        r#"
        INSERT INTO device_recovery_challenges (id, user_id, device_id, challenge_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_id, device_id, challenge_hash, expires_at, consumed_at, created_at
        "#,
    )
    .bind(id)
    .bind(input.user_id)
    .bind(input.device_id)
    .bind(input.challenge_hash)
    .bind(input.expires_at)
    .fetch_one(&self.pool)
    .await
    .map_err(map_sqlx_error)?;

    recovery_challenge_from_row(row)
}

pub async fn consume_recovery_challenge(
    &self,
    challenge_id: Uuid,
    user_id: UserId,
    device_id: DeviceId,
    challenge_hash: &str,
) -> Result<RecoveryChallengeRecord, StorageError> {
    let row = sqlx::query(
        r#"
        UPDATE device_recovery_challenges
        SET consumed_at = now()
        WHERE id = $1
          AND user_id = $2
          AND device_id = $3
          AND challenge_hash = $4
          AND consumed_at IS NULL
          AND expires_at > now()
        RETURNING id, user_id, device_id, challenge_hash, expires_at, consumed_at, created_at
        "#,
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(device_id)
    .bind(challenge_hash)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StorageError::NotFound)?;

    recovery_challenge_from_row(row)
}
```

In `crates/umbra-storage/src/convert.rs`, add:

```rust
pub(crate) fn recovery_challenge_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<RecoveryChallengeRecord, StorageError> {
    Ok(RecoveryChallengeRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        challenge_hash: row.try_get("challenge_hash")?,
        expires_at: row.try_get("expires_at")?,
        consumed_at: row.try_get("consumed_at")?,
        created_at: row.try_get("created_at")?,
    })
}
```

In `crates/umbra-storage/src/sessions.rs`, add:

```rust
pub async fn revoke_sessions_for_device(&self, device_id: Uuid) -> Result<u64, StorageError> {
    let result = sqlx::query(
        r#"
        UPDATE sessions
        SET revoked_at = now()
        WHERE device_id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(device_id)
    .execute(&self.pool)
    .await?;

    Ok(result.rows_affected())
}
```

- [ ] **Step 6: Add storage tests**

In `crates/umbra-storage/src/tests.rs`, add:

```rust
#[sqlx::test(migrator = "umbra_migrations::MIGRATOR")]
async fn postgres_devices_support_pending_trust_and_revoke(pool: sqlx::PgPool) {
    let storage = Storage::new(pool);
    let user = storage
        .create_user(CreateUser {
            id: None,
            email: "device-state@example.com".to_owned(),
            display_name: None,
            public_key: "account-public".to_owned(),
            encrypted_private_key: serde_json::json!({"encrypted": true}),
        })
        .await
        .unwrap();
    let pending = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "new laptop".to_owned(),
            public_key: Some("device-public".to_owned()),
            fingerprint: "fingerprint".to_owned(),
            state: DeviceState::Pending,
            approval_code_hash: Some("hash".to_owned()),
            approval_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
            bootstrap_public_key: Some("bootstrap-public".to_owned()),
        })
        .await
        .unwrap();

    assert_eq!(pending.state, DeviceState::Pending);
    assert_eq!(pending.bootstrap_bundle, None);

    let found = storage
        .find_pending_device_by_approval_hash(user.id, "hash")
        .await
        .unwrap();
    assert_eq!(found.id, pending.id);

    let approved = storage
        .approve_pending_device(ApprovePendingDevice {
            device_id: pending.id,
            bootstrap_bundle: serde_json::json!({"ciphertext": "opaque"}),
        })
        .await
        .unwrap();
    assert_eq!(approved.state, DeviceState::Trusted);
    assert!(approved.trusted_at.is_some());
    assert_eq!(approved.bootstrap_bundle, Some(serde_json::json!({"ciphertext": "opaque"})));

    storage.revoke_device(approved.id).await.unwrap();
    let revoked = storage.find_device_by_id(approved.id).await.unwrap();
    assert_eq!(revoked.state, DeviceState::Revoked);
    assert!(revoked.revoked_at.is_some());
}
```

Add:

```rust
#[sqlx::test(migrator = "umbra_migrations::MIGRATOR")]
async fn postgres_recovery_challenge_consumes_once(pool: sqlx::PgPool) {
    let storage = Storage::new(pool);
    let user = storage
        .create_user(CreateUser {
            id: None,
            email: "recovery-challenge@example.com".to_owned(),
            display_name: None,
            public_key: "account-public".to_owned(),
            encrypted_private_key: serde_json::json!({"encrypted": true}),
        })
        .await
        .unwrap();
    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "pending".to_owned(),
            public_key: Some("device-public".to_owned()),
            fingerprint: "fingerprint".to_owned(),
            state: DeviceState::Pending,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
        })
        .await
        .unwrap();
    let challenge = storage
        .create_recovery_challenge(CreateRecoveryChallenge {
            id: None,
            user_id: user.id,
            device_id: device.id,
            challenge_hash: "hash".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .unwrap();

    let consumed = storage
        .consume_recovery_challenge(challenge.id, user.id, device.id, "hash")
        .await
        .unwrap();
    assert!(consumed.consumed_at.is_some());

    assert!(storage
        .consume_recovery_challenge(challenge.id, user.id, device.id, "hash")
        .await
        .is_err());
}
```

- [ ] **Step 7: Run tests**

Run:

```bash
cargo test -p umbra-migrations embeds_migrations
cargo test -p umbra-storage postgres_devices_support_pending_trust_and_revoke
cargo test -p umbra-storage postgres_recovery_challenge_consumes_once
cargo test -p umbra-storage
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add crates/umbra-migrations/migrations/000005_device_trust_state.sql crates/umbra-storage/src/models.rs crates/umbra-storage/src/convert.rs crates/umbra-storage/src/devices.rs crates/umbra-storage/src/sessions.rs crates/umbra-storage/src/tests.rs
git commit -m "feat(storage): model device trust state"
```

---

### Task 3: Add Bootstrap And Recovery Crypto

**Files:**
- Modify: `crates/umbra-crypto/src/lib.rs`

- [ ] **Step 1: Add bootstrap bundle types**

In `crates/umbra-crypto/src/lib.rs`, add after `EncryptionPayloadV1`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBootstrapBundleV1 {
    pub version: u16,
    pub user_secret_key: String,
    pub kdf_params: Argon2idParams,
    pub encrypted_user_private_key: CryptoEnvelopeV1,
    pub account_public_key: String,
    pub default_vault_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBootstrapEnvelopeV1 {
    pub version: u16,
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub recipient_public_key: String,
    pub ephemeral_public_key: String,
    pub encryption: EncryptionPayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallengeEnvelopeV1 {
    pub version: u16,
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub recipient_public_key: String,
    pub ephemeral_public_key: String,
    pub encryption: EncryptionPayloadV1,
}
```

Add AAD constructors to `impl AadV1`:

```rust
pub fn device_bootstrap(device_id: impl Into<String>) -> Self {
    Self {
        app: "umbra".to_owned(),
        purpose: "device_bootstrap".to_owned(),
        schema: 1,
        vault_id: device_id.into(),
        item_id: None,
        revision: None,
        kind: None,
    }
}

pub fn recovery_challenge(device_id: impl Into<String>, challenge_id: impl Into<String>) -> Self {
    Self {
        app: "umbra".to_owned(),
        purpose: "device_recovery_challenge".to_owned(),
        schema: 1,
        vault_id: device_id.into(),
        item_id: Some(challenge_id.into()),
        revision: None,
        kind: None,
    }
}
```

- [ ] **Step 2: Add encrypt/decrypt helpers**

Add these functions near vault key wrapping helpers:

```rust
pub fn encrypt_device_bootstrap_bundle(
    recipient_public_key: &UserPublicKey,
    aad: AadV1,
    bundle: &DeviceBootstrapBundleV1,
) -> Result<DeviceBootstrapEnvelopeV1, CryptoError> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let recipient = PublicKey::from(recipient_public_key.as_bytes_array()?);
    let shared_secret = ephemeral.diffie_hellman(&recipient);
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), &aad)?;
    let payload = encrypt_payload_with_key(&wrapping_key, aad, &serde_json::to_vec(bundle)?)?;

    Ok(DeviceBootstrapEnvelopeV1 {
        version: ENVELOPE_VERSION_V1,
        envelope_type: "device_bootstrap".to_owned(),
        recipient_public_key: recipient_public_key.to_base64url(),
        ephemeral_public_key: encode_b64(ephemeral_public.as_bytes()),
        encryption: payload,
    })
}

pub fn decrypt_device_bootstrap_bundle(
    recipient_private_key: &UserPrivateKey,
    expected_aad: &AadV1,
    envelope: &DeviceBootstrapEnvelopeV1,
) -> Result<DeviceBootstrapBundleV1, CryptoError> {
    assert_supported_envelope_version(envelope.version)?;
    if envelope.envelope_type != "device_bootstrap" {
        return Err(CryptoError::MissingEnvelopeField("type"));
    }
    if &envelope.encryption.aad != expected_aad {
        return Err(CryptoError::AadMismatch);
    }
    let ephemeral_public = PublicKey::from(
        decode_b64(&envelope.ephemeral_public_key)?
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?,
    );
    let private = StaticSecret::from(recipient_private_key.as_bytes_array()?);
    let shared_secret = private.diffie_hellman(&ephemeral_public);
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), expected_aad)?;
    let plaintext = decrypt_payload_with_key(&wrapping_key, expected_aad, &envelope.encryption)?;
    serde_json::from_slice(&plaintext).map_err(|_| CryptoError::InvalidEncoding)
}

pub fn encrypt_recovery_challenge(
    recipient_public_key: &UserPublicKey,
    aad: AadV1,
    challenge: &[u8],
) -> Result<RecoveryChallengeEnvelopeV1, CryptoError> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let recipient = PublicKey::from(recipient_public_key.as_bytes_array()?);
    let shared_secret = ephemeral.diffie_hellman(&recipient);
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), &aad)?;
    let payload = encrypt_payload_with_key(&wrapping_key, aad, challenge)?;

    Ok(RecoveryChallengeEnvelopeV1 {
        version: ENVELOPE_VERSION_V1,
        envelope_type: "device_recovery_challenge".to_owned(),
        recipient_public_key: recipient_public_key.to_base64url(),
        ephemeral_public_key: encode_b64(ephemeral_public.as_bytes()),
        encryption: payload,
    })
}

pub fn decrypt_recovery_challenge(
    recipient_private_key: &UserPrivateKey,
    expected_aad: &AadV1,
    envelope: &RecoveryChallengeEnvelopeV1,
) -> Result<Vec<u8>, CryptoError> {
    assert_supported_envelope_version(envelope.version)?;
    if envelope.envelope_type != "device_recovery_challenge" {
        return Err(CryptoError::MissingEnvelopeField("type"));
    }
    if &envelope.encryption.aad != expected_aad {
        return Err(CryptoError::AadMismatch);
    }
    let ephemeral_public = PublicKey::from(
        decode_b64(&envelope.ephemeral_public_key)?
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?,
    );
    let private = StaticSecret::from(recipient_private_key.as_bytes_array()?);
    let shared_secret = private.diffie_hellman(&ephemeral_public);
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), expected_aad)?;
    decrypt_payload_with_key(&wrapping_key, expected_aad, &envelope.encryption)
}
```

Add these byte-array helpers to `UserPublicKey` and `UserPrivateKey`:

```rust
impl UserPublicKey {
    pub fn as_bytes_array(&self) -> Result<[u8; KEY_LEN], CryptoError> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)
    }
}

impl UserPrivateKey {
    pub fn as_bytes_array(&self) -> Result<[u8; KEY_LEN], CryptoError> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)
    }
}
```

Add these payload helpers above `encrypt_with_key`:

```rust
fn encrypt_payload_with_key(
    key: &Key,
    aad: AadV1,
    plaintext: &[u8],
) -> Result<EncryptionPayloadV1, CryptoError> {
    let nonce = Nonce::generate();
    let aad_bytes = aad_bytes(&aad)?;
    let cipher = XChaCha20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(
            nonce.as_xnonce(),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;

    Ok(EncryptionPayloadV1 {
        alg: "xchacha20-poly1305".to_owned(),
        nonce: nonce.to_base64url(),
        aad,
        ciphertext: encode_b64(&ciphertext),
    })
}

fn decrypt_payload_with_key(
    key: &Key,
    expected_aad: &AadV1,
    payload: &EncryptionPayloadV1,
) -> Result<Vec<u8>, CryptoError> {
    if payload.alg != "xchacha20-poly1305" {
        return Err(CryptoError::DecryptFailed);
    }
    ensure_aad(expected_aad, &payload.aad)?;

    let nonce = decode_array::<NONCE_LEN>(&payload.nonce)?;
    let ciphertext = decode_b64(&payload.ciphertext)?;
    let aad_bytes = aad_bytes(expected_aad)?;
    let cipher = XChaCha20Poly1305::new(key);

    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}
```

Then replace `encrypt_with_key` with this wrapper:

```rust
fn encrypt_with_key(
    key: &Key,
    aad: AadV1,
    plaintext: &[u8],
) -> Result<CryptoEnvelopeV1, CryptoError> {
    let payload = encrypt_payload_with_key(key, aad, plaintext)?;
    Ok(CryptoEnvelopeV1 {
        version: ENVELOPE_VERSION_V1,
        suite: DEFAULT_SUITE.to_owned(),
        nonce: payload.nonce,
        aad: payload.aad,
        ciphertext: payload.ciphertext,
    })
}
```

- [ ] **Step 3: Add crypto tests**

Add tests in `crates/umbra-crypto/src/lib.rs`:

```rust
#[test]
fn device_bootstrap_bundle_roundtrips() {
    let password = MasterPassword::new("correct horse battery staple");
    let user_secret_key = UserSecretKey::generate();
    let kdf_params = fast_params(Salt::generate().to_base64url());
    let account_kek = derive_account_kek(&password, &user_secret_key, &kdf_params).unwrap();
    let account = generate_user_keypair();
    let encrypted_private_key =
        encrypt_user_private_key(&account_kek, &account.private_key, AadV1::user_private_key("user")).unwrap();
    let bootstrap_recipient = generate_user_keypair();
    let bundle = DeviceBootstrapBundleV1 {
        version: ENVELOPE_VERSION_V1,
        user_secret_key: user_secret_key.to_base64url(),
        kdf_params,
        encrypted_user_private_key,
        account_public_key: account.public_key.to_base64url(),
        default_vault_id: Some("00000000-0000-0000-0000-000000000001".to_owned()),
    };
    let aad = AadV1::device_bootstrap("00000000-0000-0000-0000-000000000002");

    let envelope =
        encrypt_device_bootstrap_bundle(&bootstrap_recipient.public_key, aad.clone(), &bundle).unwrap();
    let decoded =
        decrypt_device_bootstrap_bundle(&bootstrap_recipient.private_key, &aad, &envelope).unwrap();

    assert_eq!(decoded, bundle);
    assert!(!format!("{decoded:?}").contains("correct horse"));
}
```

Add:

```rust
#[test]
fn device_bootstrap_bundle_fails_with_wrong_key_or_aad() {
    let recipient = generate_user_keypair();
    let wrong = generate_user_keypair();
    let account = generate_user_keypair();
    let params = fast_params(Salt::generate().to_base64url());
    let password = MasterPassword::new("password");
    let secret = UserSecretKey::generate();
    let kek = derive_account_kek(&password, &secret, &params).unwrap();
    let encrypted_private_key =
        encrypt_user_private_key(&kek, &account.private_key, AadV1::user_private_key("user")).unwrap();
    let bundle = DeviceBootstrapBundleV1 {
        version: ENVELOPE_VERSION_V1,
        user_secret_key: secret.to_base64url(),
        kdf_params: params,
        encrypted_user_private_key,
        account_public_key: account.public_key.to_base64url(),
        default_vault_id: None,
    };
    let aad = AadV1::device_bootstrap("device-a");
    let envelope = encrypt_device_bootstrap_bundle(&recipient.public_key, aad.clone(), &bundle).unwrap();

    assert!(decrypt_device_bootstrap_bundle(&wrong.private_key, &aad, &envelope).is_err());
    assert!(decrypt_device_bootstrap_bundle(
        &recipient.private_key,
        &AadV1::device_bootstrap("device-b"),
        &envelope
    )
    .is_err());
}
```

Add:

```rust
#[test]
fn recovery_challenge_roundtrips() {
    let account = generate_user_keypair();
    let aad = AadV1::recovery_challenge("device", "challenge");
    let challenge = b"random challenge bytes";

    let envelope = encrypt_recovery_challenge(&account.public_key, aad.clone(), challenge).unwrap();
    let decoded = decrypt_recovery_challenge(&account.private_key, &aad, &envelope).unwrap();

    assert_eq!(decoded, challenge);
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p umbra-crypto device_bootstrap_bundle_roundtrips
cargo test -p umbra-crypto device_bootstrap_bundle_fails_with_wrong_key_or_aad
cargo test -p umbra-crypto recovery_challenge_roundtrips
cargo test -p umbra-crypto
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-crypto/src/lib.rs
git commit -m "feat(crypto): add device bootstrap envelopes"
```

---

### Task 4: Enforce Device State In Server Auth

**Files:**
- Modify: `crates/umbra-server/src/signed_auth.rs`
- Modify: `crates/umbra-server/src/authz.rs`
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Replace trusted boolean checks**

In `crates/umbra-server/src/signed_auth.rs`, import:

```rust
use umbra_core::DeviceState;
```

Replace:

```rust
if device.user_id != session.user_id
    || !device.trusted
    || device.revoked_at.is_some()
    || device.public_key.is_none()
{
    return Err(StatusCode::UNAUTHORIZED);
}
```

with:

```rust
if device.user_id != session.user_id
    || device.state != DeviceState::Trusted
    || device.revoked_at.is_some()
    || device.public_key.is_none()
{
    return Err(StatusCode::UNAUTHORIZED);
}
```

In `crates/umbra-server/src/http.rs`, import `DeviceState`:

```rust
use umbra_core::{DeviceState, MemberState, OrgRole, VaultKind, VaultRole};
```

In `auth_login_finish`, replace trusted checks with:

```rust
if device.user_id != user.id
    || device.state != DeviceState::Trusted
    || device.revoked_at.is_some()
    || device.public_key.is_none()
{
    return Err(ServerError::Unauthorized);
}
```

- [ ] **Step 2: Add active signed device context**

In `crates/umbra-server/src/signed_auth.rs`, extend `AuthenticatedUser`:

```rust
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticatedUser {
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
}
```

Update `authenticated_user_from_headers` to read both headers:

```rust
const AUTHENTICATED_DEVICE_HEADER: &str = "x-umbra-authenticated-device";

pub(crate) fn authenticated_user_from_headers(headers: &HeaderMap) -> Option<AuthenticatedUser> {
    let user_id = headers
        .get(AUTHENTICATED_USER_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())?;
    let device_id = headers
        .get(AUTHENTICATED_DEVICE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok());
    Some(AuthenticatedUser { user_id, device_id })
}
```

In `auth_middleware`, return both values from auth helpers. Change local assignment to:

```rust
let authenticated = if let Some(authenticated) = authenticate_bearer(&state, &parts.headers).await? {
    authenticated
} else {
    authenticate_signed(&state, &parts, &body_bytes).await?
};
```

Insert headers:

```rust
let user_header = authenticated
    .user_id
    .to_string()
    .parse()
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
parts.headers.insert(AUTHENTICATED_USER_HEADER, user_header);
if let Some(device_id) = authenticated.device_id {
    let device_header = device_id
        .to_string()
        .parse()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    parts.headers.insert(AUTHENTICATED_DEVICE_HEADER, device_header);
}
```

Make `authenticate_bearer` return `Result<Option<AuthenticatedUser>, StatusCode>`:

```rust
Ok(Some(AuthenticatedUser {
    user_id: session.user_id,
    device_id: session.device_id,
}))
```

Make `authenticate_signed` return `Result<AuthenticatedUser, StatusCode>`:

```rust
Ok(AuthenticatedUser {
    user_id: session.user_id,
    device_id: Some(device_id),
})
```

In `crates/umbra-server/src/authz.rs`, add:

```rust
use crate::signed_auth::AuthenticatedUser;

pub(crate) async fn authenticate_context(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedUser, ServerError> {
    if let Some(authenticated) = authenticated_user_from_headers(headers) {
        return Ok(authenticated);
    }

    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ServerError::Unauthorized)?;
    let session = state
        .storage
        .find_active_session_by_hash(&token_hash(token))
        .await?;
    Ok(AuthenticatedUser {
        user_id: session.user_id,
        device_id: session.device_id,
    })
}
```

Change existing `authenticate` to:

```rust
pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserId, ServerError> {
    Ok(authenticate_context(state, headers).await?.user_id)
}
```

- [ ] **Step 3: Update registration device creation**

In `auth_register_finish`, update `CreateDevice`:

```rust
CreateDevice {
    id: None,
    user_id: user.id,
    name: request.initial_device.name,
    public_key: Some(request.initial_device.public_key),
    fingerprint: request.initial_device.fingerprint,
    state: DeviceState::Trusted,
    approval_code_hash: None,
    approval_expires_at: None,
    bootstrap_public_key: None,
}
```

- [ ] **Step 4: Update tests using `CreateDevice`**

Search:

```bash
rg -n "CreateDevice \\{" crates
```

For each test fixture, set:

```rust
state: DeviceState::Trusted,
approval_code_hash: None,
approval_expires_at: None,
bootstrap_public_key: None,
```

For tests that explicitly need pending devices, set `DeviceState::Pending`.

- [ ] **Step 5: Add server test for revoked device signed auth**

In `crates/umbra-server/src/tests.rs`, add:

```rust
#[tokio::test]
async fn signed_login_rejects_revoked_device_state() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = test_app(storage.clone()).await;
    let email = "revoked-signed@example.com";
    let password = b"revoked signed password";
    let signing_key = DeviceSigningKey::generate();
    let register = register_with_device_key(app.clone(), email, password, &signing_key).await;

    storage.revoke_device(register.device_id).await.unwrap();

    let finish = opaque_login_finish(
        app,
        email,
        password,
        Some(register.device_id),
    )
    .await;
    assert_eq!(finish.status, StatusCode::UNAUTHORIZED);
}
```

Add local helpers by adapting the existing `signed_login_can_create_org_and_rejects_nonce_replay` setup:

```rust
struct RegisteredDevice {
    device_id: Uuid,
}
```

The helper must use existing OPAQUE register/start/finish helpers already present in the test file.

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-server signed_login_rejects_revoked_device_state
cargo test -p umbra-server signed_login_can_create_org_and_rejects_nonce_replay
cargo test -p umbra-server
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-server/src/signed_auth.rs crates/umbra-server/src/authz.rs crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): enforce device trust state"
```

---

### Task 5: Add Server Device Trust Endpoints

**Files:**
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/error.rs`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Add utility helpers**

In `crates/umbra-server/src/http.rs`, add imports:

```rust
use sha2::{Digest, Sha256};
use umbra_protocol::{
    ApproveDeviceRequest, DeviceBootstrapResponse, DeviceResponse, PendingDeviceRequest,
    PendingDeviceResponse, PendingDeviceSummary, RecoverTrustRequest, RecoverTrustResponse,
    RecoveryChallengeStartRequest, RecoveryChallengeStartResponse,
};
```

Add helpers near response mapping functions:

```rust
fn approval_code() -> String {
    let token = random_token();
    let compact: String = token
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(8)
        .collect();
    format!("UMBRA-{}-{}", &compact[0..4], &compact[4..8]).to_uppercase()
}

fn hash_secret(value: &str) -> String {
    encode_b64(&Sha256::digest(value.as_bytes()))
}

fn device_response(device: umbra_storage::DeviceRecord) -> DeviceResponse {
    DeviceResponse {
        device_id: device.id,
        name: device.name,
        public_key: device.public_key,
        fingerprint: device.fingerprint,
        state: device.state,
        created_at: device.created_at.to_rfc3339(),
        trusted_at: device.trusted_at.map(|value| value.to_rfc3339()),
        revoked_at: device.revoked_at.map(|value| value.to_rfc3339()),
    }
}

fn pending_device_summary(device: umbra_storage::DeviceRecord) -> Result<PendingDeviceSummary, ServerError> {
    Ok(PendingDeviceSummary {
        device_id: device.id,
        name: device.name,
        fingerprint: device.fingerprint,
        bootstrap_public_key: device
            .bootstrap_public_key
            .ok_or(ServerError::BadRequest("pending device missing bootstrap public key"))?,
        approval_expires_at: device
            .approval_expires_at
            .ok_or(ServerError::BadRequest("pending device missing approval expiry"))?
            .to_rfc3339(),
        created_at: device.created_at.to_rfc3339(),
    })
}
```

- [ ] **Step 2: Add routes**

In `router`, create a `pending_device_routes` router that uses normal auth middleware but endpoint handlers will check device state:

```rust
let protected = Router::new()
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/pending", get(list_pending_devices))
        .route("/api/v1/devices/approval-lookup", post(lookup_approval_code))
        .route("/api/v1/devices/:device_id/approve", post(approve_device))
    .route("/api/v1/devices/:device_id/revoke", post(revoke_device))
    .route("/api/v1/devices/:device_id/bootstrap", get(get_device_bootstrap))
    .route("/api/v1/devices/:device_id/recovery-challenge", post(start_recovery_challenge))
    .route("/api/v1/devices/:device_id/recover-trust", post(recover_trust))
    // keep existing routes here
```

- [ ] **Step 3: Add list/pending/bootstrap handlers**

Add:

```rust
async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceResponse>>, ServerError> {
    let auth = authenticate_context(&state, &headers).await?;
    let devices = state.storage.list_devices_for_user(auth.user_id).await?;
    Ok(Json(devices.into_iter().map(device_response).collect()))
}

async fn list_pending_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PendingDeviceSummary>>, ServerError> {
    let auth = authenticate_context(&state, &headers).await?;
    let Some(device_id) = auth.device_id else {
        return Err(ServerError::Forbidden);
    };
    let current = state.storage.find_device_by_id(device_id).await?;
    if current.state != DeviceState::Trusted {
        return Err(ServerError::Forbidden);
    }
    let devices = state.storage.list_pending_devices_for_user(auth.user_id).await?;
    let summaries = devices
        .into_iter()
        .map(pending_device_summary)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(summaries))
}

async fn get_device_bootstrap(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<DeviceBootstrapResponse>, ServerError> {
    let auth = authenticate_context(&state, &headers).await?;
    if auth.device_id != Some(device_id) {
        return Err(ServerError::Forbidden);
    }
    let device = state.storage.find_device_by_id(device_id).await?;
    if device.user_id != auth.user_id {
        return Err(ServerError::Forbidden);
    }
    Ok(Json(DeviceBootstrapResponse {
        device_id,
        state: device.state,
        bootstrap_bundle: device.bootstrap_bundle,
    }))
}
```

- [ ] **Step 4: Add approval lookup, approve, and revoke handlers**

Add:

```rust
async fn lookup_approval_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<umbra_protocol::ApprovalLookupRequest>,
) -> Result<Json<PendingDeviceSummary>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let auth = authenticate_context(&state, &headers).await?;
    let Some(current_device_id) = auth.device_id else {
        return Err(ServerError::Forbidden);
    };
    let current = state.storage.find_device_by_id(current_device_id).await?;
    if current.state != DeviceState::Trusted {
        return Err(ServerError::Forbidden);
    }
    let pending = state
        .storage
        .find_pending_device_by_approval_hash(auth.user_id, &hash_secret(&request.approval_code))
        .await?;
    Ok(Json(pending_device_summary(pending)?))
}

async fn approve_device(
    State(state): State<AppState>,
    Path(_device_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ApproveDeviceRequest>,
) -> Result<Json<DeviceResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let auth = authenticate_context(&state, &headers).await?;
    let Some(current_device_id) = auth.device_id else {
        return Err(ServerError::Forbidden);
    };
    let current = state.storage.find_device_by_id(current_device_id).await?;
    if current.state != DeviceState::Trusted {
        return Err(ServerError::Forbidden);
    }
    let pending = state
        .storage
        .find_pending_device_by_approval_hash(auth.user_id, &hash_secret(&request.approval_code))
        .await?;
    let approved = state
        .storage
        .approve_pending_device(umbra_storage::ApprovePendingDevice {
            device_id: pending.id,
            bootstrap_bundle: request.bootstrap_bundle,
        })
        .await?;
    state
        .storage
        .append_audit_log(umbra_storage::AppendAuditLog {
            id: None,
            actor_user_id: Some(auth.user_id),
            vault_id: None,
            action: "device.approve".to_owned(),
            target_type: Some("device".to_owned()),
            target_id: Some(approved.id),
            metadata: json!({"approved_by_device_id": current_device_id}),
        })
        .await?;
    Ok(Json(device_response(approved)))
}

async fn revoke_device(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<DeviceResponse>, ServerError> {
    let auth = authenticate_context(&state, &headers).await?;
    let target = state.storage.find_device_by_id(device_id).await?;
    if target.user_id != auth.user_id {
        return Err(ServerError::Forbidden);
    }
    state.storage.revoke_device(device_id).await?;
    state.storage.revoke_sessions_for_device(device_id).await?;
    state
        .storage
        .append_audit_log(umbra_storage::AppendAuditLog {
            id: None,
            actor_user_id: Some(auth.user_id),
            vault_id: None,
            action: "device.revoke".to_owned(),
            target_type: Some("device".to_owned()),
            target_id: Some(device_id),
            metadata: json!({}),
        })
        .await?;
    let revoked = state.storage.find_device_by_id(device_id).await?;
    Ok(Json(device_response(revoked)))
}
```

- [ ] **Step 5: Add recovery challenge handlers**

Add:

```rust
async fn start_recovery_challenge(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<RecoveryChallengeStartRequest>,
) -> Result<Json<RecoveryChallengeStartResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.device_id != device_id {
        return Err(ServerError::BadRequest("device id mismatch"));
    }
    let auth = authenticate_context(&state, &headers).await?;
    if auth.device_id != Some(device_id) {
        return Err(ServerError::Forbidden);
    }
    let device = state.storage.find_device_by_id(device_id).await?;
    if device.user_id != auth.user_id || device.state != DeviceState::Pending {
        return Err(ServerError::Forbidden);
    }
    let user = state.storage.find_user_by_id(auth.user_id).await?;
    let account_public_key = umbra_crypto::UserPublicKey::from_base64url(&user.public_key)
        .map_err(|_| ServerError::BadRequest("invalid account public key"))?;
    let challenge = random_token();
    let challenge_id = Uuid::new_v4();
    let aad = umbra_crypto::AadV1::recovery_challenge(device_id.to_string(), challenge_id.to_string());
    let encrypted = umbra_crypto::encrypt_recovery_challenge(
        &account_public_key,
        aad,
        challenge.as_bytes(),
    )
    .map_err(|_| ServerError::BadRequest("recovery challenge encryption failed"))?;
    let expires_at = Utc::now() + Duration::minutes(10);
    state
        .storage
        .create_recovery_challenge(umbra_storage::CreateRecoveryChallenge {
            id: Some(challenge_id),
            user_id: auth.user_id,
            device_id,
            challenge_hash: hash_secret(&challenge),
            expires_at,
        })
        .await?;
    Ok(Json(RecoveryChallengeStartResponse {
        challenge_id,
        encrypted_challenge: serde_json::to_value(encrypted)?,
        expires_at: expires_at.to_rfc3339(),
    }))
}

async fn recover_trust(
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<RecoverTrustRequest>,
) -> Result<Json<RecoverTrustResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let auth = authenticate_context(&state, &headers).await?;
    if auth.device_id != Some(device_id) {
        return Err(ServerError::Forbidden);
    }
    state
        .storage
        .consume_recovery_challenge(
            request.challenge_id,
            auth.user_id,
            device_id,
            &hash_secret(&request.challenge_response),
        )
        .await?;
    let trusted = state.storage.mark_device_trusted(device_id).await?;
    Ok(Json(RecoverTrustResponse {
        device_id,
        state: trusted.state,
    }))
}
```

- [ ] **Step 6: Modify OPAQUE login finish for pending devices**

In `auth_login_finish`, after OPAQUE finish and before existing `(session, session_token, auth_scheme)` branch, handle `request.pending_device` when `device_id` is absent:

```rust
let (session, session_token, auth_scheme, pending_device) =
    if let Some(pending_request) = request.pending_device {
        ensure_protocol(pending_request.protocol_version)?;
        let approval_code = approval_code();
        let approval_expires_at = Utc::now() + Duration::minutes(10);
        let device = state
            .storage
            .create_device(CreateDevice {
                id: None,
                user_id: user.id,
                name: pending_request.name,
                public_key: Some(pending_request.public_key),
                fingerprint: pending_request.fingerprint,
                state: DeviceState::Pending,
                approval_code_hash: Some(hash_secret(&approval_code)),
                approval_expires_at: Some(approval_expires_at),
                bootstrap_public_key: Some(pending_request.bootstrap_public_key),
            })
            .await?;
        let token = random_token();
        let session = state
            .storage
            .create_session(CreateSession {
                id: None,
                user_id: user.id,
                device_id: Some(device.id),
                token_hash: token_hash(&token),
                auth_scheme: "bearer".to_owned(),
                expires_at,
            })
            .await?;
        (
            session,
            Some(token),
            "pending".to_owned(),
            Some(PendingDeviceResponse {
                device_id: device.id,
                session_id: session.id,
                approval_code,
                fingerprint: device.fingerprint,
                expires_at: approval_expires_at.to_rfc3339(),
            }),
        )
    } else if let Some(device_id) = request.device_id {
        // existing trusted signed login branch, returning pending_device None
    } else {
        // existing legacy bearer login branch, returning pending_device None
    };
```

Return:

```rust
Ok(Json(OpaqueLoginFinishResponse {
    user_id: user.id,
    session_id: session.id,
    session_token,
    auth_scheme,
    encrypted_private_key: user.encrypted_private_key,
    pending_device,
}))
```

- [ ] **Step 7: Add HTTP tests**

Add tests in `crates/umbra-server/src/tests.rs`:

```rust
#[tokio::test]
async fn pending_device_cannot_access_sync() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = test_app(storage).await;
    let pending = login_pending_device(app.clone(), "pending-sync@example.com", b"password").await;

    let (status, _body): (StatusCode, serde_json::Value) = bearer_json_request(
        app,
        &pending.session_token,
        "/api/v1/sync",
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id: pending.device_id,
            vaults: vec![],
        },
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}
```

Add:

```rust
#[tokio::test]
async fn trusted_device_approves_pending_device_and_pending_downloads_bootstrap() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = test_app(storage).await;
    let trusted = register_and_signed_login(app.clone(), "approve@example.com", b"password").await;
    let pending = login_pending_device_existing_user(app.clone(), "approve@example.com", b"password").await;

    let (status, lookup): (StatusCode, PendingDeviceSummary) = signed_json_request(
        app.clone(),
        SignedAuth {
            session_id: trusted.session_id,
            device_id: trusted.device_id,
            signing_key: trusted.signing_key.clone(),
        },
        "/api/v1/devices/approval-lookup",
        &ApprovalLookupRequest {
            protocol_version: PROTOCOL_VERSION,
            approval_code: pending.approval_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup.device_id, pending.device_id);

    let (status, approved): (StatusCode, DeviceResponse) = signed_json_request(
        app.clone(),
        SignedAuth {
            session_id: trusted.session_id,
            device_id: trusted.device_id,
            signing_key: trusted.signing_key.clone(),
        },
        &format!("/api/v1/devices/{}/approve", pending.device_id),
        &ApproveDeviceRequest {
            protocol_version: PROTOCOL_VERSION,
            approval_code: pending.approval_code.clone(),
            bootstrap_bundle: json!({"encrypted": "bundle"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(approved.state, DeviceState::Trusted);

    let (status, bootstrap): (StatusCode, DeviceBootstrapResponse) = bearer_get_request(
        app,
        &pending.session_token,
        &format!("/api/v1/devices/{}/bootstrap", pending.device_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bootstrap.bootstrap_bundle, Some(json!({"encrypted": "bundle"})));
}
```

Add:

```rust
#[tokio::test]
async fn recovery_trust_requires_valid_challenge_response() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = test_app(storage).await;
    let pending = login_pending_device(app.clone(), "recover@example.com", b"password").await;

    let (status, challenge): (StatusCode, RecoveryChallengeStartResponse) = bearer_json_request(
        app.clone(),
        &pending.session_token,
        &format!("/api/v1/devices/{}/recovery-challenge", pending.device_id),
        &RecoveryChallengeStartRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id: pending.device_id,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _body): (StatusCode, serde_json::Value) = bearer_json_request(
        app,
        &pending.session_token,
        &format!("/api/v1/devices/{}/recover-trust", pending.device_id),
        &RecoverTrustRequest {
            protocol_version: PROTOCOL_VERSION,
            challenge_id: challenge.challenge_id,
            challenge_response: "wrong".to_owned(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
```

Add helper functions by adapting existing `json_request` and `signed_json_request`:

```rust
async fn bearer_json_request<T, R>(
    app: Router,
    token: &str,
    path: &str,
    body: &T,
) -> (StatusCode, R)
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    decode_response(response).await
}
```

Create the corresponding `bearer_get_request`.

- [ ] **Step 8: Run tests**

Run:

```bash
cargo test -p umbra-server pending_device_cannot_access_sync
cargo test -p umbra-server trusted_device_approves_pending_device_and_pending_downloads_bootstrap
cargo test -p umbra-server recovery_trust_requires_valid_challenge_response
cargo test -p umbra-server
```

Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-server/src/http.rs crates/umbra-server/src/error.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): add device trust endpoints"
```

---

### Task 6: Add CLI Device Command Shapes

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add parser tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_device_commands() {
    let list = Cli::parse_from(["umbra", "device", "list"]);
    assert!(matches!(list.command, Command::Device(DeviceCommand::List)));

    let pending = Cli::parse_from(["umbra", "device", "pending"]);
    assert!(matches!(pending.command, Command::Device(DeviceCommand::Pending)));

    let approve = Cli::parse_from(["umbra", "device", "approve", "UMBRA-7K4Q-2M9D"]);
    assert!(matches!(
        approve.command,
        Command::Device(DeviceCommand::Approve { code }) if code == "UMBRA-7K4Q-2M9D"
    ));

    let finish = Cli::parse_from(["umbra", "device", "finish"]);
    assert!(matches!(finish.command, Command::Device(DeviceCommand::Finish)));

    let recover = Cli::parse_from(["umbra", "device", "recover"]);
    assert!(matches!(recover.command, Command::Device(DeviceCommand::Recover)));

    let revoke = Cli::parse_from([
        "umbra",
        "device",
        "revoke",
        "00000000-0000-0000-0000-000000000001",
    ]);
    assert!(matches!(
        revoke.command,
        Command::Device(DeviceCommand::Revoke { device_id })
            if device_id == uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    ));
}
```

- [ ] **Step 2: Add `DeviceCommand`**

In `crates/umbra-cli/src/main.rs`, update import:

```rust
use umbra_core::{DeviceId, ItemId, ItemKind, RevisionId, VaultId};
```

Add command variant:

```rust
#[command(subcommand)]
Device(DeviceCommand),
```

Add enum after `CacheCommand`:

```rust
#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    List,
    Pending,
    Approve {
        code: String,
    },
    Finish,
    Recover,
    Revoke {
        device_id: DeviceId,
    },
}
```

Update the `use crate::{ ... }` import in `commands.rs` to include `DeviceCommand`.

- [ ] **Step 3: Run tests**

Run:

```bash
cargo test -p umbra-cli parses_device_commands
cargo test -p umbra-cli
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): add device commands"
```

---

### Task 7: Implement CLI Pending Login And Device Finish

**Files:**
- Modify: `crates/umbra-cli/src/config.rs`
- Modify: `crates/umbra-cli/src/opaque.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add pending fields to profile config**

In `crates/umbra-cli/src/config.rs`, add fields to `ProfileConfig`:

```rust
#[serde(default)]
pub pending_bootstrap_private_key: Option<String>,
#[serde(default)]
pub pending_approval_code: Option<String>,
```

Add defaults:

```rust
pending_bootstrap_private_key: None,
pending_approval_code: None,
```

Add redacted debug:

```rust
.field(
    "pending_bootstrap_private_key",
    &self.pending_bootstrap_private_key.as_ref().map(|_| "[redacted]"),
)
.field("pending_approval_code", &self.pending_approval_code)
```

- [ ] **Step 2: Add pending login to opaque client**

In `crates/umbra-cli/src/opaque.rs`, change `login` signature:

```rust
pub async fn login(
    client: &PublicHttpClient,
    email: &str,
    password: &[u8],
    device_id: Option<uuid::Uuid>,
    pending_device: Option<PendingDeviceRequest>,
) -> Result<OpaqueLoginFinishResponse, CliError>
```

Update request:

```rust
OpaqueLoginFinishRequest {
    protocol_version: PROTOCOL_VERSION,
    login_id: start_response.login_id,
    device_id,
    pending_device,
    credential_finalization: encode_b64(login_finish.message.serialize().as_slice()),
}
```

Update all existing callers:

```rust
crate::opaque::login(&client, &email, password.as_bytes(), Some(device_id), None).await?;
```

- [ ] **Step 3: Generate bootstrap key on login without existing device**

In `crates/umbra-cli/src/commands.rs`, in `Command::Login`, replace the hard error for missing `device_id` with pending login setup:

```rust
let password = rpassword::prompt_password("Master password: ")?;
let client = PublicHttpClient::new(&profile_snapshot.server_url)?;
let (device_id, device_key, pending_bootstrap_key, pending_device) =
    if let Some(device_id) = profile_snapshot.device_id {
        (Some(device_id), None, None, None)
    } else {
        let device_name = dialoguer::Input::<String>::new()
            .with_prompt("Device name")
            .default("CLI device".to_owned())
            .interact_text()?;
        let device_key = DeviceSigningKey::generate();
        let bootstrap_key = umbra_crypto::generate_user_keypair();
        let pending = umbra_protocol::PendingDeviceRequest {
            protocol_version: PROTOCOL_VERSION,
            name: device_name,
            public_key: device_key.public_key_base64url(),
            fingerprint: device_key.fingerprint(),
            bootstrap_public_key: bootstrap_key.public_key.to_base64url(),
        };
        (None, Some(device_key), Some(bootstrap_key), Some(pending))
    };
let response =
    crate::opaque::login(&client, &email, password.as_bytes(), device_id, pending_device).await?;
```

After response:

```rust
if let Some(device_key) = device_key {
    profile_config.device_private_key = Some(device_key.to_base64url());
}
if let Some(bootstrap_key) = pending_bootstrap_key {
    profile_config.pending_bootstrap_private_key = Some(bootstrap_key.private_key.to_base64url());
}
profile_config.email = Some(email);
profile_config.user_id = Some(response.user_id);
profile_config.session_id = Some(response.session_id);
profile_config.legacy_session_token = response.session_token;
if let Some(pending) = response.pending_device {
    profile_config.device_id = Some(pending.device_id);
    profile_config.pending_approval_code = Some(pending.approval_code.clone());
    save_config(&config)?;
    println!("device pending approval");
    println!("Code: {}", pending.approval_code);
    println!("Fingerprint: {}", pending.fingerprint);
    println!("Approve from a trusted device with: umbra device approve {}", pending.approval_code);
    return Ok(());
}
```

For trusted login, clear pending fields:

```rust
profile_config.pending_bootstrap_private_key = None;
profile_config.pending_approval_code = None;
```

- [ ] **Step 4: Implement `device finish`**

In `commands.rs`, add branch:

```rust
Command::Device(DeviceCommand::Finish) => {
    let profile = active_profile(&config)?;
    let device_id = profile.device_id.ok_or(CliError::Input("profile has no pending device id"))?;
    let bootstrap_private = profile
        .pending_bootstrap_private_key
        .as_deref()
        .ok_or(CliError::Input("profile has no pending bootstrap key"))?;
    let client = UmbraHttpClient::new(profile)?;
    let response: umbra_protocol::DeviceBootstrapResponse = client
        .get(&format!("/api/v1/devices/{device_id}/bootstrap"))
        .await?;
    let Some(bundle_value) = response.bootstrap_bundle else {
        return Err(CliError::Input("bootstrap bundle not ready"));
    };
    let envelope: umbra_crypto::DeviceBootstrapEnvelopeV1 = serde_json::from_value(bundle_value)?;
    let private_key = umbra_crypto::UserPrivateKey::from_base64url(bootstrap_private)?;
    let aad = AadV1::device_bootstrap(device_id.to_string());
    let bundle = umbra_crypto::decrypt_device_bootstrap_bundle(&private_key, &aad, &envelope)?;
    let profile_config = active_profile_mut(&mut config);
    profile_config.user_secret_key = Some(bundle.user_secret_key);
    profile_config.kdf_params = Some(bundle.kdf_params);
    profile_config.encrypted_user_private_key = Some(serde_json::to_value(bundle.encrypted_user_private_key)?);
    profile_config.client_public_key = Some(bundle.account_public_key);
    profile_config.default_vault_id = bundle
        .default_vault_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| CliError::Input("invalid default vault id in bootstrap bundle"))?;
    profile_config.pending_bootstrap_private_key = None;
    profile_config.pending_approval_code = None;
    save_config(&config)?;
    println!("device trusted and bootstrap complete");
    Ok(())
}
```

- [ ] **Step 5: Add tests for config roundtrip**

In `crates/umbra-cli/src/tests.rs`, extend `config_roundtrips_toml` expected profile with pending fields, or add:

```rust
#[test]
fn profile_config_redacts_pending_bootstrap_private_key() {
    let profile = ProfileConfig {
        pending_bootstrap_private_key: Some("secret-bootstrap".to_owned()),
        pending_approval_code: Some("UMBRA-1234-5678".to_owned()),
        ..ProfileConfig::default()
    };

    let debug = format!("{profile:?}");

    assert!(!debug.contains("secret-bootstrap"));
    assert!(debug.contains("pending_approval_code"));
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-cli profile_config_redacts_pending_bootstrap_private_key
cargo test -p umbra-cli parses_device_commands
cargo test -p umbra-cli
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/config.rs crates/umbra-cli/src/opaque.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): support pending device login"
```

---

### Task 8: Implement CLI Device List, Pending, Approve, Recover, Revoke

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add render helpers**

In `commands.rs`, add:

```rust
fn render_devices(
    output: OutputMode,
    devices: &[umbra_protocol::DeviceResponse],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(devices);
    }
    let rows = devices
        .iter()
        .map(|device| {
            vec![
                device.device_id.to_string(),
                device.name.clone(),
                format!("{:?}", device.state),
                device.fingerprint.clone(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["device_id", "name", "state", "fingerprint"], &rows);
    Ok(())
}

fn render_pending_devices(
    output: OutputMode,
    devices: &[umbra_protocol::PendingDeviceSummary],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(devices);
    }
    let rows = devices
        .iter()
        .map(|device| {
            vec![
                device.device_id.to_string(),
                device.name.clone(),
                device.fingerprint.clone(),
                device.approval_expires_at.clone(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["device_id", "name", "fingerprint", "expires_at"], &rows);
    Ok(())
}
```

- [ ] **Step 2: Implement list and pending**

Add command branches:

```rust
Command::Device(DeviceCommand::List) => {
    let profile = active_profile(&config)?;
    let client = UmbraHttpClient::new(profile)?;
    let devices: Vec<umbra_protocol::DeviceResponse> = client.get("/api/v1/devices").await?;
    render_devices(output, &devices)
}
Command::Device(DeviceCommand::Pending) => {
    let profile = active_profile(&config)?;
    let client = UmbraHttpClient::new(profile)?;
    let devices: Vec<umbra_protocol::PendingDeviceSummary> =
        client.get("/api/v1/devices/pending").await?;
    render_pending_devices(output, &devices)
}
```

- [ ] **Step 3: Implement approve**

Add helper:

```rust
fn bootstrap_bundle_from_profile(
    profile: &crate::config::ProfileConfig,
    target_device_id: Uuid,
    target_bootstrap_public_key: &str,
) -> Result<serde_json::Value, CliError> {
    let recipient = UserPublicKey::from_base64url(target_bootstrap_public_key)?;
    let encrypted_private_key: CryptoEnvelopeV1 = profile
        .encrypted_user_private_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| serde_json::from_value(value).map_err(CliError::from))?;
    let bundle = umbra_crypto::DeviceBootstrapBundleV1 {
        version: 1,
        user_secret_key: profile
            .user_secret_key
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?,
        kdf_params: profile
            .kdf_params
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?,
        encrypted_user_private_key,
        account_public_key: profile
            .client_public_key
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?,
        default_vault_id: profile.default_vault_id.map(|id| id.to_string()),
    };
    let envelope = umbra_crypto::encrypt_device_bootstrap_bundle(
        &recipient,
        AadV1::device_bootstrap(target_device_id.to_string()),
        &bundle,
    )?;
    Ok(serde_json::to_value(envelope)?)
}
```

Add branch:

```rust
Command::Device(DeviceCommand::Approve { code }) => {
    let profile = active_profile(&config)?;
    let client = UmbraHttpClient::new(profile)?;
    let target: umbra_protocol::PendingDeviceSummary = client
        .post(
            "/api/v1/devices/approval-lookup",
            &umbra_protocol::ApprovalLookupRequest {
                protocol_version: PROTOCOL_VERSION,
                approval_code: code.clone(),
            },
        )
        .await?;
    let bundle = bootstrap_bundle_from_profile(
        profile,
        target.device_id,
        &target.bootstrap_public_key,
    )?;
    let response: umbra_protocol::DeviceResponse = client
        .post(
            &format!("/api/v1/devices/{}/approve", target.device_id),
            &umbra_protocol::ApproveDeviceRequest {
                protocol_version: PROTOCOL_VERSION,
                approval_code: code,
                bootstrap_bundle: bundle,
            },
        )
        .await?;
    if output.is_json() {
        print_json(&response)
    } else {
        println!("approved device: {}", response.device_id);
        Ok(())
    }
}
```

- [ ] **Step 4: Implement recover**

Add branch:

```rust
Command::Device(DeviceCommand::Recover) => {
    let profile = active_profile(&config)?;
    let device_id = profile.device_id.ok_or(CliError::Input("profile has no device id"))?;
    let password = rpassword::prompt_password("Master password: ")?;
    let secret_key = rpassword::prompt_password("Emergency kit / user secret key: ")?;
    let public_key = UserPublicKey::from_base64url(
        profile
            .client_public_key
            .as_deref()
            .ok_or(CliError::MissingCryptoMaterial)?,
    )?;
    let encrypted_private_key_value = profile
        .encrypted_user_private_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)?;
    let kdf_params = profile.kdf_params.clone().ok_or(CliError::MissingCryptoMaterial)?;
    let user_secret_key = umbra_crypto::UserSecretKey::from_base64url(&secret_key)?;
    let encrypted_private_key: CryptoEnvelopeV1 = serde_json::from_value(encrypted_private_key_value)?;
    let account_kek = umbra_crypto::derive_account_kek(
        &MasterPassword::new(password.into_bytes()),
        &user_secret_key,
        &kdf_params,
    )?;
    let private_key = umbra_crypto::decrypt_user_private_key(
        &account_kek,
        &AadV1::user_private_key(public_key.to_base64url()),
        &encrypted_private_key,
    )?;
    let client = UmbraHttpClient::new(profile)?;
    let challenge: umbra_protocol::RecoveryChallengeStartResponse = client
        .post(
            &format!("/api/v1/devices/{device_id}/recovery-challenge"),
            &umbra_protocol::RecoveryChallengeStartRequest {
                protocol_version: PROTOCOL_VERSION,
                device_id,
            },
        )
        .await?;
    let envelope: umbra_crypto::RecoveryChallengeEnvelopeV1 =
        serde_json::from_value(challenge.encrypted_challenge)?;
    let aad = AadV1::recovery_challenge(device_id.to_string(), challenge.challenge_id.to_string());
    let challenge_bytes = umbra_crypto::decrypt_recovery_challenge(&private_key, &aad, &envelope)?;
    let challenge_response = String::from_utf8(challenge_bytes)
        .map_err(|_| CliError::Input("invalid recovery challenge encoding"))?;
    let response: umbra_protocol::RecoverTrustResponse = client
        .post(
            &format!("/api/v1/devices/{device_id}/recover-trust"),
            &umbra_protocol::RecoverTrustRequest {
                protocol_version: PROTOCOL_VERSION,
                challenge_id: challenge.challenge_id,
                challenge_response,
            },
        )
        .await?;
    let profile_config = active_profile_mut(&mut config);
    profile_config.user_secret_key = Some(secret_key);
    profile_config.pending_bootstrap_private_key = None;
    profile_config.pending_approval_code = None;
    save_config(&config)?;
    if output.is_json() {
        print_json(&response)
    } else {
        println!("device recovered and trusted");
        Ok(())
    }
}
```

- [ ] **Step 5: Implement revoke**

Add branch:

```rust
Command::Device(DeviceCommand::Revoke { device_id }) => {
    let profile = active_profile(&config)?;
    let client = UmbraHttpClient::new(profile)?;
    let response: umbra_protocol::DeviceResponse = client
        .post(&format!("/api/v1/devices/{device_id}/revoke"), &serde_json::json!({}))
        .await?;
    if output.is_json() {
        print_json(&response)
    } else {
        println!("revoked device: {device_id}");
        println!("Rotate vault keys for sensitive vaults: umbra crypto rotate-vault-key <vault>");
        Ok(())
    }
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-cli parses_device_commands
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs crates/umbra-protocol/src/lib.rs crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(cli): manage trusted devices"
```

---

### Task 9: End-To-End Tests And Docs

**Files:**
- Modify: `crates/umbra-server/src/tests.rs`
- Modify: `README.md`
- Modify: `docs/protocol.md`
- Modify: `docs/threat-model.md`

- [ ] **Step 1: Add end-to-end server test**

In `crates/umbra-server/src/tests.rs`, add:

```rust
#[tokio::test]
async fn multi_device_approval_and_revoke_flow() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = test_app(storage).await;
    let device_a = register_and_signed_login(app.clone(), "multi-device@example.com", b"password").await;
    let device_b = login_pending_device_existing_user(app.clone(), "multi-device@example.com", b"password").await;

    let (status, lookup): (StatusCode, PendingDeviceSummary) = signed_json_request(
        app.clone(),
        SignedAuth {
            session_id: device_a.session_id,
            device_id: device_a.device_id,
            signing_key: device_a.signing_key.clone(),
        },
        "/api/v1/devices/approval-lookup",
        &ApprovalLookupRequest {
            protocol_version: PROTOCOL_VERSION,
            approval_code: device_b.approval_code.clone(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup.device_id, device_b.device_id);

    let (status, approved): (StatusCode, DeviceResponse) = signed_json_request(
        app.clone(),
        SignedAuth {
            session_id: device_a.session_id,
            device_id: device_a.device_id,
            signing_key: device_a.signing_key.clone(),
        },
        &format!("/api/v1/devices/{}/approve", device_b.device_id),
        &ApproveDeviceRequest {
            protocol_version: PROTOCOL_VERSION,
            approval_code: device_b.approval_code,
            bootstrap_bundle: json!({"encrypted": "bundle"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(approved.state, DeviceState::Trusted);

    let (status, revoked): (StatusCode, DeviceResponse) = signed_json_request(
        app,
        SignedAuth {
            session_id: device_a.session_id,
            device_id: device_a.device_id,
            signing_key: device_a.signing_key,
        },
        &format!("/api/v1/devices/{}/revoke", device_b.device_id),
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked.state, DeviceState::Revoked);
}
```

- [ ] **Step 2: Document README usage**

In `README.md`, add after the current CLI happy path:

```markdown
## Multi-Device Trust

Registering the first device creates a trusted device. A second device logs in with the account password, but starts as pending until approved:

```bash
# on the new device
umbra login --profile laptop-2
umbra device finish

# on an existing trusted device
umbra device pending
umbra device approve UMBRA-7K4Q-2M9D
```

If every trusted device is lost, recover with the emergency kit / user secret key:

```bash
umbra login --profile recovered
umbra device recover
```

Disconnect a device:

```bash
umbra device list
umbra device revoke <device-id>
```

Revoking a device stops future server sync and signed sessions. It cannot erase secrets already seen by that device. Rotate vault keys for sensitive vaults after device loss.
```

- [ ] **Step 3: Document protocol**

In `docs/protocol.md`, add a "Device trust" section:

```markdown
## Device Trust

OPAQUE proves the account password, but it does not make a device trusted by itself.

Known trusted devices receive signed sessions. Unknown devices can complete OPAQUE login as pending devices and receive a limited session that can only poll bootstrap state or complete recovery.

Primary approval flow:

1. Pending device sends signing public key, fingerprint, and bootstrap public key during login finish.
2. Server creates `devices.state = pending` and returns an approval code.
3. Trusted device looks up the approval code, encrypts a bootstrap bundle to the pending device bootstrap public key, and approves.
4. Pending device downloads and decrypts the bootstrap bundle locally.

Recovery flow:

1. Pending device logs in through OPAQUE.
2. User enters emergency kit / `user_secret_key`.
3. Client decrypts the account private key locally.
4. Server sends an encrypted recovery challenge to the account public key.
5. Client decrypts and returns the challenge response.
6. Server marks the current device trusted.
```

- [ ] **Step 4: Document threat model**

In `docs/threat-model.md`, add:

```markdown
## Device Trust Limits

Device revoke stops future server access for that device. It does not erase local cache, vault keys, or secrets that were already available on the revoked device.

After a device is lost or suspected compromised, the user should revoke the device and rotate vault keys for sensitive vaults. Real third-party secrets that were visible on the device, such as API tokens, should also be rotated at their source.
```

- [ ] **Step 5: Run full verification**

Run:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-server/src/tests.rs README.md docs/protocol.md docs/threat-model.md
git commit -m "docs(devices): document multi-device trust"
```

---

### Task 10: Final Verification And Push

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run final verification**

Run:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 2: Inspect git**

Run:

```bash
git status --short --branch
git log --oneline --decorate -n 12
```

Expected:

```txt
## main...origin/main [ahead N]
```

with a clean working tree.

- [ ] **Step 3: Push main**

Run:

```bash
git push origin main
```

Expected: push succeeds.

---

## Self-Review

Spec coverage:

- Explicit device states are covered in Tasks 1 and 2.
- Pending device login is covered in Tasks 5 and 7.
- Trusted-device approval and encrypted bootstrap are covered in Tasks 3, 5, and 8.
- Recovery with password plus emergency kit and account-key challenge is covered in Tasks 3, 5, and 8.
- Revoke and session invalidation are covered in Tasks 2, 5, and 8.
- CLI commands are covered in Tasks 6, 7, and 8.
- Tests and docs are covered in Tasks 1 through 10.

Placeholder scan:

- Approval lookup is a first-class protocol and server endpoint before CLI approval encrypts the bootstrap bundle.
- No steps rely on unspecified secret handling or plaintext server access.

Type consistency:

- `DeviceState` is defined in core and imported by protocol/storage/server.
- `PendingDeviceRequest`, `PendingDeviceResponse`, `DeviceResponse`, `PendingDeviceSummary`, `ApproveDeviceRequest`, `DeviceBootstrapResponse`, `RecoveryChallengeStartRequest`, `RecoveryChallengeStartResponse`, `RecoverTrustRequest`, and `RecoverTrustResponse` are used consistently across server and CLI tasks.
- `devices.state` is the authority after Task 2; `trusted` remains compatibility storage only.
