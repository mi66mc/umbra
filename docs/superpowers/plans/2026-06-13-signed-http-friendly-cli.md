# Signed HTTP Friendly CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Umbra materially usable from the CLI by adding OPAQUE register/login, multiple local profiles, signed HTTP requests that do not send reusable bearer tokens, and friendlier interactive commands for common vault/item flows.

**Architecture:** Add a small shared `umbra-auth` crate for request-signing canonicalization so CLI and server cannot drift. The server will continue supporting legacy bearer tokens for compatibility, but the CLI will use signed sessions by default: login returns a non-secret `session_id`, and every protected request is signed with the local device private signing key plus nonce/timestamp/body hash. CLI config becomes profile-based so one user can keep multiple accounts/servers and switch between them.

**Tech Stack:** Rust 1.88, Axum middleware, SQLx/PostgreSQL migrations, OPAQUE, Ed25519 request signatures, SHA-256 body hashes, Clap, Reqwest, Dialoguer, Serde/TOML, existing Umbra crates.

---

## Security Scope

This plan makes HTTP safer by removing reusable bearer tokens from CLI traffic. It protects against passive sniffing of a session token and basic replay.

It does not make plain HTTP equivalent to HTTPS:

- paths, host, timing, body sizes, metadata, vault ids, item ids, and ciphertexts still travel visibly;
- first-contact active MITM during registration/login is still a separate problem unless the client pins/verifies server identity;
- signed requests prove possession of a device private key, but they do not encrypt the HTTP transport.

The concrete goal here is:

```txt
No reusable bearer token leaves the CLI during normal CLI use.
Every protected CLI request is bound to method + path + body hash + timestamp + nonce + session_id + device_id.
Server rejects stale timestamps and nonce replay.
```

## Current State

Implemented now:

- Server OPAQUE API exists:
  - `POST /api/v1/auth/register/start`
  - `POST /api/v1/auth/register/finish`
  - `POST /api/v1/auth/login/start`
  - `POST /api/v1/auth/login/finish`
- CLI does not wrap OPAQUE yet.
- CLI currently uses:
  - `umbra auth token set`
  - `umbra vault list`
  - `umbra vault create`
  - `umbra item create`
  - `umbra item update`
  - `umbra sync run`
- Server auth currently reads `Authorization: Bearer <token>`.
- `sessions` stores `token_hash`.
- `devices` already has `public_key`, `fingerprint`, `trusted`, and `revoked_at`.

## File Structure

Create:

- `crates/umbra-auth/Cargo.toml`: shared request-signing crate manifest.
- `crates/umbra-auth/src/lib.rs`: canonical request, body hash, Ed25519 sign/verify helpers, header constants.
- `crates/umbra-migrations/migrations/000003_signed_sessions.sql`: nonce replay table and session scheme columns.
- `crates/umbra-server/src/signed_auth.rs`: Axum middleware for signed/bearer auth.
- `crates/umbra-cli/src/keys.rs`: local device signing key generation/encoding/fingerprint.
- `crates/umbra-cli/src/opaque.rs`: CLI OPAQUE register/login client flow.
- `crates/umbra-cli/src/output.rs`: JSON/text output helpers.

Modify:

- `Cargo.toml`: add `crates/umbra-auth` and workspace dependencies.
- `Cargo.lock`: updated by Cargo.
- `crates/umbra-protocol/src/lib.rs`: signed-session protocol fields.
- `crates/umbra-storage/src/models.rs`: signed session/nonce models.
- `crates/umbra-storage/src/sessions.rs`: session lookup by id, nonce insert, signed session creation.
- `crates/umbra-storage/src/devices.rs`: find device by id.
- `crates/umbra-storage/src/tests.rs`: signed session and nonce replay DB tests.
- `crates/umbra-server/src/main.rs`: add `signed_auth` module.
- `crates/umbra-server/src/http.rs`: split public/protected routes and return signed login sessions.
- `crates/umbra-server/src/authz.rs`: consume authenticated user context instead of bearer-only lookup.
- `crates/umbra-server/src/tests.rs`: signed auth integration tests.
- `crates/umbra-server/Cargo.toml`: add `umbra-auth`, `ed25519-dalek`, `hmac` only if needed.
- `crates/umbra-cli/Cargo.toml`: add OPAQUE, signing, prompt, and auth deps.
- `crates/umbra-cli/src/main.rs`: friendlier command tree.
- `crates/umbra-cli/src/config.rs`: profile-based config.
- `crates/umbra-cli/src/http.rs`: signed request client.
- `crates/umbra-cli/src/commands.rs`: register/login/profile/interactive vault commands.
- `crates/umbra-cli/src/tests.rs`: parser/config/signing tests.
- `README.md`: update CLI usage.
- `docs/protocol.md`: signed HTTP authentication.
- `docs/threat-model.md`: plain HTTP limitations.

## UX Target

Primary CLI after this plan:

```bash
umbra register --server http://127.0.0.1:8080 --email miguel@example.com
umbra login --profile personal
umbra profile list
umbra profile use personal
umbra vault list
umbra vault create
umbra item create --vault <VAULT_ID> --kind api_key --envelope-json '{"ciphertext":"..."}'
umbra sync --vault <VAULT_ID>
```

Still intentionally not in this plan:

- polished client-side encryption UX for items;
- local encrypted vault cache;
- OS keychain integration;
- server identity pinning for active MITM protection;
- ratatui full-screen TUI.

This plan uses `dialoguer` prompts, not a full-screen TUI. That gives a usable terminal flow now without committing to a UI framework too early.

---

### Task 1: Add Shared Request Signing Crate

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/umbra-auth/Cargo.toml`
- Create: `crates/umbra-auth/src/lib.rs`

- [ ] **Step 1: Add failing tests for canonical signing**

Create `crates/umbra-auth/Cargo.toml`:

```toml
[package]
name = "umbra-auth"
description = "Umbra HTTP request authentication helpers."
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
version.workspace = true

[dependencies]
base64ct.workspace = true
ed25519-dalek.workspace = true
rand_core.workspace = true
serde.workspace = true
sha2.workspace = true
thiserror.workspace = true
uuid.workspace = true
```

Create `crates/umbra-auth/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use uuid::Uuid;

    #[test]
    fn body_hash_is_base64url_sha256() {
        let hash = body_sha256_b64(br#"{"hello":"world"}"#);

        assert_eq!(hash, "k6I5cakU5erL8KjSUVTNownDwccvu5kU1Hxg88toFYg");
    }

    #[test]
    fn canonical_request_is_stable() {
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let parts = SignedRequestParts {
            method: "POST".to_owned(),
            path_and_query: "/api/v1/sync?x=1".to_owned(),
            body_sha256: "bodyhash".to_owned(),
            timestamp_unix: 1_700_000_000,
            nonce: "nonce-1".to_owned(),
            session_id,
            device_id,
        };

        assert_eq!(
            canonical_request(&parts),
            "UMBRA-SIGNED-REQUEST-V1\nPOST\n/api/v1/sync?x=1\nbodyhash\n1700000000\nnonce-1\n00000000-0000-0000-0000-000000000001\n00000000-0000-0000-0000-000000000002"
        );
    }

    #[test]
    fn signed_request_verifies_and_tampering_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let parts = SignedRequestParts {
            method: "GET".to_owned(),
            path_and_query: "/api/v1/vaults".to_owned(),
            body_sha256: body_sha256_b64(b""),
            timestamp_unix: 1_700_000_000,
            nonce: "nonce-2".to_owned(),
            session_id,
            device_id,
        };

        let signature = sign_request(&signing_key, &parts);

        verify_request(&verifying_key, &parts, &signature).unwrap();

        let mut tampered = parts.clone();
        tampered.path_and_query = "/api/v1/orgs".to_owned();
        assert_eq!(
            verify_request(&verifying_key, &tampered, &signature),
            Err(AuthError::InvalidSignature)
        );
    }
}
```

- [ ] **Step 2: Add workspace member and dependency**

In root `Cargo.toml`, add:

```toml
    "crates/umbra-auth",
```

to `[workspace].members`.

Add workspace dependency:

```toml
ed25519-dalek = { version = "2", features = ["rand_core"] }
```

- [ ] **Step 3: Run tests and verify failure**

Run:

```bash
cargo test -p umbra-auth
```

Expected: compile fails because functions/types are missing.

- [ ] **Step 4: Implement request signing helpers**

Replace `crates/umbra-auth/src/lib.rs` with:

```rust
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SIGNATURE_SCHEME: &str = "UMBRA-SIGNED-REQUEST-V1";
pub const HEADER_SESSION_ID: &str = "umbra-session-id";
pub const HEADER_DEVICE_ID: &str = "umbra-device-id";
pub const HEADER_TIMESTAMP: &str = "umbra-timestamp";
pub const HEADER_NONCE: &str = "umbra-nonce";
pub const HEADER_BODY_SHA256: &str = "umbra-body-sha256";
pub const HEADER_SIGNATURE: &str = "umbra-signature";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequestParts {
    pub method: String,
    pub path_and_query: String,
    pub body_sha256: String,
    pub timestamp_unix: i64,
    pub nonce: String,
    pub session_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("invalid signing key")]
    InvalidSigningKey,
    #[error("invalid verifying key")]
    InvalidVerifyingKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid encoding")]
    InvalidEncoding,
}

pub fn body_sha256_b64(body: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(body))
}

pub fn canonical_request(parts: &SignedRequestParts) -> String {
    [
        SIGNATURE_SCHEME.to_owned(),
        parts.method.to_uppercase(),
        parts.path_and_query.clone(),
        parts.body_sha256.clone(),
        parts.timestamp_unix.to_string(),
        parts.nonce.clone(),
        parts.session_id.to_string(),
        parts.device_id.to_string(),
    ]
    .join("\n")
}

pub fn sign_request(signing_key: &SigningKey, parts: &SignedRequestParts) -> String {
    let signature = signing_key.sign(canonical_request(parts).as_bytes());
    Base64UrlUnpadded::encode_string(&signature.to_bytes())
}

pub fn verify_request(
    verifying_key: &VerifyingKey,
    parts: &SignedRequestParts,
    signature_b64: &str,
) -> Result<(), AuthError> {
    let bytes =
        Base64UrlUnpadded::decode_vec(signature_b64).map_err(|_| AuthError::InvalidEncoding)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| AuthError::InvalidSignature)?;
    verifying_key
        .verify(canonical_request(parts).as_bytes(), &signature)
        .map_err(|_| AuthError::InvalidSignature)
}

pub fn signing_key_to_b64(signing_key: &SigningKey) -> String {
    Base64UrlUnpadded::encode_string(&signing_key.to_bytes())
}

pub fn verifying_key_to_b64(verifying_key: &VerifyingKey) -> String {
    Base64UrlUnpadded::encode_string(verifying_key.as_bytes())
}

pub fn signing_key_from_b64(value: &str) -> Result<SigningKey, AuthError> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| AuthError::InvalidEncoding)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidSigningKey)?;
    Ok(SigningKey::from_bytes(&array))
}

pub fn verifying_key_from_b64(value: &str) -> Result<VerifyingKey, AuthError> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| AuthError::InvalidEncoding)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidVerifyingKey)?;
    VerifyingKey::from_bytes(&array).map_err(|_| AuthError::InvalidVerifyingKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use uuid::Uuid;

    #[test]
    fn body_hash_is_base64url_sha256() {
        let hash = body_sha256_b64(br#"{"hello":"world"}"#);

        assert_eq!(hash, "k6I5cakU5erL8KjSUVTNownDwccvu5kU1Hxg88toFYg");
    }

    #[test]
    fn canonical_request_is_stable() {
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let parts = SignedRequestParts {
            method: "POST".to_owned(),
            path_and_query: "/api/v1/sync?x=1".to_owned(),
            body_sha256: "bodyhash".to_owned(),
            timestamp_unix: 1_700_000_000,
            nonce: "nonce-1".to_owned(),
            session_id,
            device_id,
        };

        assert_eq!(
            canonical_request(&parts),
            "UMBRA-SIGNED-REQUEST-V1\nPOST\n/api/v1/sync?x=1\nbodyhash\n1700000000\nnonce-1\n00000000-0000-0000-0000-000000000001\n00000000-0000-0000-0000-000000000002"
        );
    }

    #[test]
    fn signed_request_verifies_and_tampering_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let parts = SignedRequestParts {
            method: "GET".to_owned(),
            path_and_query: "/api/v1/vaults".to_owned(),
            body_sha256: body_sha256_b64(b""),
            timestamp_unix: 1_700_000_000,
            nonce: "nonce-2".to_owned(),
            session_id,
            device_id,
        };

        let signature = sign_request(&signing_key, &parts);

        verify_request(&verifying_key, &parts, &signature).unwrap();

        let mut tampered = parts.clone();
        tampered.path_and_query = "/api/v1/orgs".to_owned();
        assert_eq!(
            verify_request(&verifying_key, &tampered, &signature),
            Err(AuthError::InvalidSignature)
        );
    }
}
```

- [ ] **Step 5: Run tests and commit**

Run:

```bash
cargo test -p umbra-auth
cargo fmt --all
```

Expected: tests pass.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/umbra-auth
git commit -m "feat(auth): add signed request primitives"
```

---

### Task 2: Add Signed Session Storage

**Files:**
- Create: `crates/umbra-migrations/migrations/000003_signed_sessions.sql`
- Modify: `crates/umbra-storage/src/models.rs`
- Modify: `crates/umbra-storage/src/sessions.rs`
- Modify: `crates/umbra-storage/src/devices.rs`
- Modify: `crates/umbra-storage/src/tests.rs`

- [ ] **Step 1: Add migration**

Create `crates/umbra-migrations/migrations/000003_signed_sessions.sql`:

```sql
ALTER TABLE sessions
    ADD COLUMN auth_scheme text NOT NULL DEFAULT 'bearer'
        CHECK (auth_scheme IN ('bearer', 'signed'));

CREATE TABLE session_nonces (
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    nonce text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, nonce)
);

CREATE INDEX session_nonces_created_at_idx ON session_nonces(created_at);
```

- [ ] **Step 2: Add failing storage tests**

In `crates/umbra-storage/src/tests.rs`, add this test after `postgres_migrations_create_required_schema`:

```rust
#[tokio::test]
#[serial(postgres)]
async fn postgres_signed_sessions_reject_nonce_replay() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let user = create_test_user(&storage, "signed@example.com").await;
    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "signed laptop".to_owned(),
            public_key: Some("device-public-key".to_owned()),
            fingerprint: "signed-device".to_owned(),
            trusted: true,
        })
        .await
        .unwrap();
    let session = storage
        .create_session(CreateSession {
            id: None,
            user_id: user.id,
            device_id: Some(device.id),
            token_hash: "server-only-session-marker".to_owned(),
            auth_scheme: "signed".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
        })
        .await
        .unwrap();

    let loaded = storage.find_active_session_by_id(session.id).await.unwrap();
    assert_eq!(loaded.auth_scheme, "signed");
    assert_eq!(loaded.device_id, Some(device.id));

    storage.remember_session_nonce(session.id, "nonce-1").await.unwrap();
    assert!(matches!(
        storage.remember_session_nonce(session.id, "nonce-1").await,
        Err(StorageError::Conflict)
    ));
}
```

- [ ] **Step 3: Run storage test and verify failure**

Run:

```bash
cargo test -p umbra-storage postgres_signed_sessions_reject_nonce_replay
```

Expected: fail because `auth_scheme`, `find_active_session_by_id`, and `remember_session_nonce` do not exist.

- [ ] **Step 4: Extend storage models**

In `crates/umbra-storage/src/models.rs`, change `CreateSession` to:

```rust
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub id: Option<Uuid>,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub auth_scheme: String,
    pub expires_at: DateTime<Utc>,
}
```

Change `SessionRecord` to:

```rust
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub auth_scheme: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
```

- [ ] **Step 5: Update session storage**

In `crates/umbra-storage/src/sessions.rs`, update `create_session` query:

```rust
INSERT INTO sessions (id, user_id, device_id, token_hash, auth_scheme, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, device_id, token_hash, auth_scheme, created_at, expires_at, revoked_at
```

Bind `input.auth_scheme`.

Update `find_active_session_by_hash` select:

```rust
SELECT id, user_id, device_id, token_hash, auth_scheme, created_at, expires_at, revoked_at
```

Add:

```rust
pub async fn find_active_session_by_id(
    &self,
    session_id: Uuid,
) -> Result<SessionRecord, StorageError> {
    let row = sqlx::query(
        r#"
        SELECT id, user_id, device_id, token_hash, auth_scheme, created_at, expires_at, revoked_at
        FROM sessions
        WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()
        "#,
    )
    .bind(session_id)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StorageError::NotFound)?;

    session_from_row(row)
}

pub async fn remember_session_nonce(
    &self,
    session_id: Uuid,
    nonce: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        r#"
        INSERT INTO session_nonces (session_id, nonce)
        VALUES ($1, $2)
        "#,
    )
    .bind(session_id)
    .bind(nonce)
    .execute(&self.pool)
    .await
    .map_err(map_sqlx_error)?;

    Ok(())
}
```

- [ ] **Step 6: Update row conversion**

In `crates/umbra-storage/src/convert.rs`, add:

```rust
auth_scheme: row.try_get("auth_scheme")?,
```

to `session_from_row`.

- [ ] **Step 7: Add device lookup**

In `crates/umbra-storage/src/devices.rs`, add:

```rust
pub async fn find_device_by_id(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError> {
    let row = sqlx::query(
        r#"
        SELECT id, user_id, name, public_key, fingerprint, trusted, created_at, last_seen_at, revoked_at
        FROM devices
        WHERE id = $1
        "#,
    )
    .bind(device_id)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StorageError::NotFound)?;

    device_from_row(row)
}
```

- [ ] **Step 8: Update existing CreateSession call sites**

Find all `CreateSession {` and add:

```rust
auth_scheme: "bearer".to_owned(),
```

except signed tests, which use `"signed"`.

Run:

```bash
rg "CreateSession" crates
```

Expected: server login handler and tests compile.

- [ ] **Step 9: Run storage tests and commit**

Run:

```bash
cargo test -p umbra-storage
cargo test --all --no-run
cargo fmt --all
```

Expected: pass locally; DB tests skip if `UMBRA_TEST_DATABASE_URL` is unset.

Commit:

```bash
git add crates/umbra-migrations/migrations/000003_signed_sessions.sql crates/umbra-storage/src crates/umbra-server/src
git commit -m "feat(storage): add signed session replay tracking"
```

---

### Task 3: Extend Protocol For Signed Sessions

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`

- [ ] **Step 1: Add failing protocol tests**

Inside `#[cfg(test)] mod tests`, add:

```rust
#[test]
fn login_finish_request_can_bind_device() {
    let device_id = Uuid::new_v4();
    let request = OpaqueLoginFinishRequest {
        protocol_version: PROTOCOL_VERSION,
        login_id: Uuid::new_v4(),
        device_id: Some(device_id),
        credential_finalization: "final".to_owned(),
    };

    let encoded = serde_json::to_value(&request).unwrap();

    assert_eq!(encoded["device_id"], json!(device_id));
}

#[test]
fn login_finish_response_can_omit_bearer_token_for_signed_session() {
    let response = OpaqueLoginFinishResponse {
        user_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        session_token: None,
        auth_scheme: "signed".to_owned(),
        encrypted_private_key: json!({"ciphertext": "encrypted"}),
    };

    let encoded = serde_json::to_value(&response).unwrap();

    assert_eq!(encoded["auth_scheme"], json!("signed"));
    assert_eq!(encoded["session_token"], serde_json::Value::Null);
}
```

- [ ] **Step 2: Run protocol tests and verify failure**

Run:

```bash
cargo test -p umbra-protocol
```

Expected: compile failure for missing fields.

- [ ] **Step 3: Update protocol structs**

Change `OpaqueLoginFinishRequest`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishRequest {
    pub protocol_version: u16,
    pub login_id: uuid::Uuid,
    pub device_id: Option<DeviceId>,
    pub credential_finalization: String,
}
```

Change `OpaqueLoginFinishResponse`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishResponse {
    pub user_id: UserId,
    pub session_id: uuid::Uuid,
    pub session_token: Option<String>,
    pub auth_scheme: String,
    pub encrypted_private_key: serde_json::Value,
}
```

- [ ] **Step 4: Update compile errors in server tests**

Find construction of `OpaqueLoginFinishRequest` and add:

```rust
device_id: None,
```

Find uses of `finish.session_token` and update test helper:

```rust
finish.session_token.expect("legacy bearer login returns token")
```

- [ ] **Step 5: Run tests and commit**

Run:

```bash
cargo test -p umbra-protocol
cargo test -p umbra-server --no-run
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-protocol/src/lib.rs crates/umbra-server/src/tests.rs
git commit -m "feat(protocol): add signed login session fields"
```

---

### Task 4: Add Server Signed Auth Middleware

**Files:**
- Create: `crates/umbra-server/src/signed_auth.rs`
- Modify: `crates/umbra-server/src/main.rs`
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/authz.rs`
- Modify: `crates/umbra-server/Cargo.toml`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Add server dependencies**

In `crates/umbra-server/Cargo.toml`, add:

```toml
ed25519-dalek.workspace = true
umbra-auth = { path = "../umbra-auth" }
```

- [ ] **Step 2: Add failing signed request test**

In `crates/umbra-server/src/tests.rs`, add imports:

```rust
use ed25519_dalek::SigningKey;
use umbra_auth::{
    SignedRequestParts, body_sha256_b64, sign_request, signing_key_to_b64, verifying_key_to_b64,
};
```

Add helper:

```rust
async fn signed_json_request<T, R>(
    app: Router,
    method: Method,
    uri: &str,
    session_id: uuid::Uuid,
    device_id: uuid::Uuid,
    signing_key: &SigningKey,
    nonce: &str,
    body: &T,
) -> (StatusCode, R)
where
    T: Serialize,
    R: for<'de> Deserialize<'de>,
{
    let body_bytes = serde_json::to_vec(body).unwrap();
    let body_hash = body_sha256_b64(&body_bytes);
    let parts = SignedRequestParts {
        method: method.to_string(),
        path_and_query: uri.to_owned(),
        body_sha256: body_hash.clone(),
        timestamp_unix: chrono::Utc::now().timestamp(),
        nonce: nonce.to_owned(),
        session_id,
        device_id,
    };
    let signature = sign_request(signing_key, &parts);
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header("umbra-session-id", session_id.to_string())
                .header("umbra-device-id", device_id.to_string())
                .header("umbra-timestamp", parts.timestamp_unix.to_string())
                .header("umbra-nonce", nonce)
                .header("umbra-body-sha256", body_hash)
                .header("umbra-signature", signature)
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
```

Add test:

```rust
#[tokio::test]
#[serial(postgres)]
async fn signed_session_can_list_vaults_and_rejects_replay() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key_to_b64(&verifying_key);

    let (token, user_id, device_id) = register_and_login_with_device_key(
        app.clone(),
        "signed-http@example.com",
        b"signed password",
        public_key,
    )
    .await;

    let (status, finish): (StatusCode, OpaqueLoginFinishResponse) = login_with_device(
        app.clone(),
        "signed-http@example.com",
        b"signed password",
        Some(device_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(finish.user_id, user_id);
    assert_eq!(finish.auth_scheme, "signed");
    assert_eq!(finish.session_token, None);

    let (status, _vaults): (StatusCode, Vec<VaultResponse>) = signed_json_request(
        app.clone(),
        Method::GET,
        "/api/v1/vaults",
        finish.session_id,
        device_id,
        &signing_key,
        "nonce-1",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _body): (StatusCode, serde_json::Value) = signed_json_request(
        app,
        Method::GET,
        "/api/v1/vaults",
        finish.session_id,
        device_id,
        &signing_key,
        "nonce-1",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    assert!(!token.is_empty(), "legacy helper still returns a bearer token for existing tests");
}
```

Add helpers `register_and_login_with_device_key` and `login_with_device` by extracting current `register_and_login` logic. The helper must pass `device_id: Some(device_id)` in login finish when testing signed login.

- [ ] **Step 3: Run server test and verify failure**

Run:

```bash
cargo test -p umbra-server signed_session_can_list_vaults_and_rejects_replay
```

Expected: compile or runtime failure because signed middleware is missing.

- [ ] **Step 4: Create signed auth module**

Create `crates/umbra-server/src/signed_auth.rs`:

```rust
use axum::{
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use umbra_auth::{
    HEADER_BODY_SHA256, HEADER_DEVICE_ID, HEADER_NONCE, HEADER_SESSION_ID, HEADER_SIGNATURE,
    HEADER_TIMESTAMP, SignedRequestParts, body_sha256_b64, verify_request, verifying_key_from_b64,
};
use uuid::Uuid;

use crate::state::AppState;
use crate::util::token_hash;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticatedUser {
    pub user_id: Uuid,
}

pub(crate) async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers().clone();
    if let Some(user_id) = authenticate_bearer(&state, &headers).await? {
        request.extensions_mut().insert(AuthenticatedUser { user_id });
        return Ok(next.run(request).await);
    }

    let (parts, verifying_key) = signed_parts_and_key(&state, request.method().as_str(), request.uri().path_and_query().map(|p| p.as_str()).unwrap_or(request.uri().path()), &headers).await?;
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if body_sha256_b64(&body) != parts.body_sha256 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let signature = header_str(&headers, HEADER_SIGNATURE)?;
    verify_request(&verifying_key, &parts, signature).map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .storage
        .remember_session_nonce(parts.session_id, &parts.nonce)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session = state
        .storage
        .find_active_session_by_id(parts.session_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut request = Request::builder()
        .method(parts.method.as_str())
        .uri(parts.path_and_query.as_str())
        .body(Body::from(body))
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    *request.headers_mut() = headers;
    request.extensions_mut().insert(AuthenticatedUser {
        user_id: session.user_id,
    });

    Ok(next.run(request).await)
}

async fn authenticate_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Uuid>, StatusCode> {
    let Some(token) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Ok(None);
    };
    let session = state
        .storage
        .find_active_session_by_hash(&token_hash(token))
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Some(session.user_id))
}

async fn signed_parts_and_key(
    state: &AppState,
    method: &str,
    path_and_query: &str,
    headers: &HeaderMap,
) -> Result<(SignedRequestParts, VerifyingKey), StatusCode> {
    let session_id = header_str(headers, HEADER_SESSION_ID)?
        .parse::<Uuid>()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let device_id = header_str(headers, HEADER_DEVICE_ID)?
        .parse::<Uuid>()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let timestamp_unix = header_str(headers, HEADER_TIMESTAMP)?
        .parse::<i64>()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if (Utc::now().timestamp() - timestamp_unix).abs() > 300 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let nonce = header_str(headers, HEADER_NONCE)?.to_owned();
    let body_sha256 = header_str(headers, HEADER_BODY_SHA256)?.to_owned();
    let session = state
        .storage
        .find_active_session_by_id(session_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if session.auth_scheme != "signed" || session.device_id != Some(device_id) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let device = state
        .storage
        .find_device_by_id(device_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if device.user_id != session.user_id || !device.trusted || device.revoked_at.is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let public_key = device.public_key.ok_or(StatusCode::UNAUTHORIZED)?;
    let verifying_key = verifying_key_from_b64(&public_key).map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok((
        SignedRequestParts {
            method: method.to_owned(),
            path_and_query: path_and_query.to_owned(),
            body_sha256,
            timestamp_unix,
            nonce,
            session_id,
            device_id,
        },
        verifying_key,
    ))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, StatusCode> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)
}
```

If reconstructing `Request` from builder drops version/extensions unexpectedly, instead split request into parts before reading the body and rebuild with `Request::from_parts(parts, Body::from(body))`.

- [ ] **Step 5: Wire middleware and auth context**

In `crates/umbra-server/src/main.rs`, add:

```rust
mod signed_auth;
```

In `crates/umbra-server/src/http.rs`, build protected routes separately:

```rust
use axum::middleware::from_fn_with_state;
use crate::signed_auth::{AuthenticatedUser, auth_middleware};
```

Public routes stay unprotected:

```rust
Router::new()
    .route("/health", get(health))
    .route("/ready", get(ready))
    .route("/api/v1/auth/register/start", post(auth_register_start))
    .route("/api/v1/auth/register/finish", post(auth_register_finish))
    .route("/api/v1/auth/login/start", post(auth_login_start))
    .route("/api/v1/auth/login/finish", post(auth_login_finish))
    .merge(protected_router(state.clone()))
    .layer(TraceLayer::new_for_http())
    .with_state(state)
```

Create:

```rust
fn protected_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs", post(create_org).get(list_orgs))
        .route("/api/v1/orgs/:org_id", get(get_org))
        .route("/api/v1/orgs/:org_id/members", get(list_org_members).post(add_org_member))
        .route("/api/v1/orgs/:org_id/vaults", post(create_org_vault))
        .route("/api/v1/vaults", post(create_personal_vault).get(list_vaults))
        .route("/api/v1/sync", post(sync))
        .route("/api/v1/vaults/:vault_id/items", post(create_item))
        .route("/api/v1/vaults/:vault_id/items/:item_id", post(update_item).put(update_item))
        .route("/api/v1/vaults/:vault_id/members", post(add_vault_member))
        .route("/api/v1/vaults/:vault_id/members/:user_id", delete(remove_vault_member))
        .route("/api/v1/vaults/:vault_id/rotation-status", get(rotation_status))
        .route("/api/v1/vaults/:vault_id/rotate-key", post(rotate_key))
        .route_layer(from_fn_with_state(state, auth_middleware))
}
```

Change protected handlers from `headers: HeaderMap` to `Extension(auth): Extension<AuthenticatedUser>` and replace:

```rust
let user_id = authenticate(&state, &headers).await?;
```

with:

```rust
let user_id = auth.user_id;
```

Keep authz helpers like `ensure_vault_writer`.

Delete or stop using bearer-only `authenticate` from `authz.rs`.

- [ ] **Step 6: Update login finish response**

In `auth_login_finish`, if `request.device_id` is `Some(device_id)`:

```rust
let session = state.storage.create_session(CreateSession {
    id: None,
    user_id: user.id,
    device_id: Some(device_id),
    token_hash: token_hash(&random_token()),
    auth_scheme: "signed".to_owned(),
    expires_at,
}).await?;

return Ok(Json(OpaqueLoginFinishResponse {
    user_id: user.id,
    session_id: session.id,
    session_token: None,
    auth_scheme: "signed".to_owned(),
    encrypted_private_key: user.encrypted_private_key,
}));
```

If `device_id` is `None`, keep legacy bearer:

```rust
let token = random_token();
let session = state.storage.create_session(CreateSession {
    id: None,
    user_id: user.id,
    device_id: None,
    token_hash: token_hash(&token),
    auth_scheme: "bearer".to_owned(),
    expires_at,
}).await?;

Ok(Json(OpaqueLoginFinishResponse {
    user_id: user.id,
    session_id: session.id,
    session_token: Some(token),
    auth_scheme: "bearer".to_owned(),
    encrypted_private_key: user.encrypted_private_key,
}))
```

- [ ] **Step 7: Run server tests and commit**

Run:

```bash
cargo test -p umbra-server
cargo clippy -p umbra-server --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass locally; DB tests skip if env missing.

Commit:

```bash
git add crates/umbra-server crates/umbra-storage crates/umbra-protocol crates/umbra-migrations Cargo.toml Cargo.lock
git commit -m "feat(server): authenticate signed HTTP sessions"
```

---

### Task 5: Make CLI Config Profile-Based

**Files:**
- Modify: `crates/umbra-cli/src/config.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add failing profile config tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn profile_config_roundtrips_and_selects_active_profile() {
    let mut config = CliConfig::default();
    config.active_profile = "personal".to_owned();
    config.profiles.insert(
        "personal".to_owned(),
        ProfileConfig {
            server_url: "http://127.0.0.1:8080".to_owned(),
            user_id: Some(uuid::Uuid::new_v4()),
            device_id: Some(uuid::Uuid::new_v4()),
            session_id: Some(uuid::Uuid::new_v4()),
            device_private_key: Some("private".to_owned()),
            legacy_session_token: None,
        },
    );

    let encoded = toml::to_string(&config).unwrap();
    let decoded: CliConfig = toml::from_str(&encoded).unwrap();

    assert_eq!(decoded.active_profile, "personal");
    assert_eq!(decoded.active_profile().unwrap().server_url, "http://127.0.0.1:8080");
}
```

Update existing config tests to use `ProfileConfig`.

- [ ] **Step 2: Run CLI tests and verify failure**

Run:

```bash
cargo test -p umbra-cli profile_config_roundtrips_and_selects_active_profile
```

Expected: compile failure because profile types do not exist.

- [ ] **Step 3: Replace config model**

In `crates/umbra-cli/src/config.rs`, replace `CliConfig` with:

```rust
use std::{collections::BTreeMap, path::PathBuf};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::error::CliError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliConfig {
    pub active_profile: String,
    pub profiles: BTreeMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub server_url: String,
    pub user_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub device_private_key: Option<String>,
    pub legacy_session_token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert("default".to_owned(), ProfileConfig::default());
        Self {
            active_profile: "default".to_owned(),
            profiles,
        }
    }
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".to_owned(),
            user_id: None,
            device_id: None,
            session_id: None,
            device_private_key: None,
            legacy_session_token: None,
        }
    }
}

impl CliConfig {
    pub fn active_profile(&self) -> Result<&ProfileConfig, CliError> {
        self.profiles
            .get(&self.active_profile)
            .ok_or_else(|| CliError::MissingProfile(self.active_profile.clone()))
    }

    pub fn active_profile_mut(&mut self) -> Result<&mut ProfileConfig, CliError> {
        let active = self.active_profile.clone();
        self.profiles
            .get_mut(&active)
            .ok_or(CliError::MissingProfile(active))
    }

    pub fn ensure_profile_mut(&mut self, name: &str) -> &mut ProfileConfig {
        self.profiles.entry(name.to_owned()).or_default()
    }
}
```

Keep existing `config_path`, `load_config`, and `save_config`.

- [ ] **Step 4: Add profile commands to parser**

In `crates/umbra-cli/src/main.rs`, add:

```rust
#[command(subcommand)]
Profile(ProfileCommand),
```

to `Command`.

Add:

```rust
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    List,
    Use { name: String },
}
```

Add global profile option:

```rust
#[arg(long, global = true)]
pub profile: Option<String>,
```

to `Cli`.

In `main`, before `commands::run`, if `cli.profile` is present, override `config.active_profile`.

- [ ] **Step 5: Implement profile commands**

In `crates/umbra-cli/src/commands.rs`, import `ProfileCommand`.

Add match arms:

```rust
Command::Profile(ProfileCommand::List) => {
    for (name, profile) in &config.profiles {
        let marker = if name == &config.active_profile { "*" } else { " " };
        println!("{marker} {name} {}", profile.server_url);
    }
    Ok(())
}
Command::Profile(ProfileCommand::Use { name }) => {
    config.ensure_profile_mut(&name);
    config.active_profile = name;
    save_config(&config)?;
    println!("active profile: {}", config.active_profile);
    Ok(())
}
```

Update existing command code from `config.server_url/session_token` to `config.active_profile()?`.

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli/src
git commit -m "feat(cli): support multiple profiles"
```

---

### Task 6: Add CLI Device Keys And Signed HTTP Client

**Files:**
- Modify: `crates/umbra-cli/Cargo.toml`
- Create: `crates/umbra-cli/src/keys.rs`
- Modify: `crates/umbra-cli/src/http.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add dependencies**

In `crates/umbra-cli/Cargo.toml`, add:

```toml
chrono.workspace = true
ed25519-dalek.workspace = true
opaque-ke.workspace = true
rand_core.workspace = true
base64ct.workspace = true
sha2.workspace = true
umbra-auth = { path = "../umbra-auth" }
```

- [ ] **Step 2: Add key tests**

Create `crates/umbra-cli/src/keys.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_device_key_roundtrips() {
        let key = DeviceSigningKey::generate();
        let encoded = key.to_base64url();
        let decoded = DeviceSigningKey::from_base64url(&encoded).unwrap();

        assert_eq!(decoded.public_key_base64url(), key.public_key_base64url());
        assert!(key.fingerprint().starts_with("SHA256:"));
    }
}
```

- [ ] **Step 3: Run test and verify failure**

Run:

```bash
cargo test -p umbra-cli generated_device_key_roundtrips
```

Expected: compile failure for missing key type.

- [ ] **Step 4: Implement device key wrapper**

Replace `crates/umbra-cli/src/keys.rs`:

```rust
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use umbra_auth::{signing_key_from_b64, signing_key_to_b64, verifying_key_to_b64};

use crate::error::CliError;

#[derive(Clone)]
pub struct DeviceSigningKey {
    signing_key: SigningKey,
}

impl DeviceSigningKey {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_base64url(value: &str) -> Result<Self, CliError> {
        Ok(Self {
            signing_key: signing_key_from_b64(value)?,
        })
    }

    pub fn to_base64url(&self) -> String {
        signing_key_to_b64(&self.signing_key)
    }

    pub fn public_key_base64url(&self) -> String {
        verifying_key_to_b64(&self.signing_key.verifying_key())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.signing_key.verifying_key().as_bytes());
        format!("SHA256:{}", Base64UrlUnpadded::encode_string(&digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_device_key_roundtrips() {
        let key = DeviceSigningKey::generate();
        let encoded = key.to_base64url();
        let decoded = DeviceSigningKey::from_base64url(&encoded).unwrap();

        assert_eq!(decoded.public_key_base64url(), key.public_key_base64url());
        assert!(key.fingerprint().starts_with("SHA256:"));
    }
}
```

Add to `CliError`:

```rust
#[error("auth error: {0}")]
Auth(#[from] umbra_auth::AuthError),
#[error("profile is not logged in")]
NotLoggedIn,
```

- [ ] **Step 5: Update HTTP client to sign requests**

In `crates/umbra-cli/src/http.rs`, change `UmbraHttpClient::new` to accept `&ProfileConfig`.

Add fields:

```rust
session_id: Option<uuid::Uuid>,
device_id: Option<uuid::Uuid>,
device_key: Option<DeviceSigningKey>,
legacy_token: Option<String>,
```

In `send`, serialize body bytes in `post`/`put`, and for all requests sign:

```rust
let nonce = uuid::Uuid::new_v4().to_string();
let body_hash = body_sha256_b64(&body_bytes);
let timestamp_unix = chrono::Utc::now().timestamp();
let parts = SignedRequestParts {
    method: method.to_string(),
    path_and_query: path.to_owned(),
    body_sha256: body_hash.clone(),
    timestamp_unix,
    nonce: nonce.clone(),
    session_id,
    device_id,
};
let signature = sign_request(device_key.signing_key(), &parts);
```

Set headers:

```rust
.header(HEADER_SESSION_ID, session_id.to_string())
.header(HEADER_DEVICE_ID, device_id.to_string())
.header(HEADER_TIMESTAMP, timestamp_unix.to_string())
.header(HEADER_NONCE, nonce)
.header(HEADER_BODY_SHA256, body_hash)
.header(HEADER_SIGNATURE, signature)
```

If signed fields are missing but `legacy_token` exists, use bearer fallback. If neither exists, return `CliError::NotLoggedIn`.

- [ ] **Step 6: Add signing client tests**

In `crates/umbra-cli/src/tests.rs`, add parser/config tests confirming signed profile fields roundtrip:

```rust
#[test]
fn signed_profile_roundtrips() {
    let mut profile = ProfileConfig::default();
    profile.session_id = Some(uuid::Uuid::new_v4());
    profile.device_id = Some(uuid::Uuid::new_v4());
    profile.device_private_key = Some("private".to_owned());

    let encoded = toml::to_string(&profile).unwrap();
    let decoded: ProfileConfig = toml::from_str(&encoded).unwrap();

    assert_eq!(decoded.session_id, profile.session_id);
    assert_eq!(decoded.device_private_key.as_deref(), Some("private"));
}
```

- [ ] **Step 7: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli Cargo.toml Cargo.lock
git commit -m "feat(cli): sign HTTP requests with device keys"
```

---

### Task 7: Add CLI Register And Login

**Files:**
- Create: `crates/umbra-cli/src/opaque.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/error.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add CLI command parser tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_register_and_login_commands() {
    let register = Cli::parse_from([
        "umbra",
        "register",
        "--server",
        "http://127.0.0.1:8080",
        "--email",
        "miguel@example.com",
        "--profile",
        "personal",
    ]);
    assert!(matches!(register.command, Command::Register { .. }));

    let login = Cli::parse_from(["umbra", "login", "--profile", "personal"]);
    assert!(matches!(login.command, Command::Login { .. }));
}
```

- [ ] **Step 2: Run CLI tests and verify failure**

Run:

```bash
cargo test -p umbra-cli parses_register_and_login_commands
```

Expected: compile failure because commands do not exist.

- [ ] **Step 3: Add command shapes**

In `crates/umbra-cli/src/main.rs`, add top-level commands:

```rust
Register {
    #[arg(long)]
    server: String,
    #[arg(long)]
    email: String,
    #[arg(long)]
    profile: String,
    #[arg(long)]
    display_name: Option<String>,
},
Login {
    #[arg(long)]
    profile: Option<String>,
},
```

Keep `auth token set` as explicit legacy/debug command.

- [ ] **Step 4: Implement OPAQUE client module**

Create `crates/umbra-cli/src/opaque.rs`:

```rust
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use umbra_protocol::{
    DeviceRegisterRequest, OpaqueLoginFinishRequest, OpaqueLoginFinishResponse,
    OpaqueLoginStartRequest, OpaqueLoginStartResponse, OpaqueRegisterFinishRequest,
    OpaqueRegisterStartRequest, OpaqueRegisterStartResponse, PROTOCOL_VERSION, RegisterResponse,
};

use crate::error::CliError;
use crate::http::PublicHttpClient;
use crate::keys::DeviceSigningKey;

pub async fn register(
    client: &PublicHttpClient,
    email: &str,
    display_name: Option<String>,
    password: &[u8],
    device_name: &str,
    device_key: &DeviceSigningKey,
) -> Result<RegisterResponse, CliError> {
    let registration_start = ClientRegistration::<crate::OpaqueCipherSuite>::start(&mut OsRng, password)
        .map_err(|_| CliError::Opaque("registration start failed"))?;
    let start_response: OpaqueRegisterStartResponse = client
        .post(
            "/api/v1/auth/register/start",
            &OpaqueRegisterStartRequest {
                protocol_version: PROTOCOL_VERSION,
                email: email.to_owned(),
                registration_request: crate::http::encode_b64(registration_start.message.serialize().as_slice()),
            },
        )
        .await?;
    let registration_response = RegistrationResponse::<crate::OpaqueCipherSuite>::deserialize(
        &crate::http::decode_b64(&start_response.registration_response)?,
    )
    .map_err(|_| CliError::Opaque("invalid registration response"))?;
    let registration_finish = registration_start
        .state
        .finish(
            &mut OsRng,
            password,
            registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| CliError::Opaque("registration finish failed"))?;

    client
        .post(
            "/api/v1/auth/register/finish",
            &OpaqueRegisterFinishRequest {
                protocol_version: PROTOCOL_VERSION,
                registration_id: start_response.registration_id,
                email: email.to_owned(),
                display_name,
                public_key: "account-public-key-mvp".to_owned(),
                encrypted_private_key: serde_json::json!({"mvp": "encrypted-private-key-not-unlocked-yet"}),
                initial_device: DeviceRegisterRequest {
                    name: device_name.to_owned(),
                    public_key: device_key.public_key_base64url(),
                    fingerprint: device_key.fingerprint(),
                },
                registration_upload: crate::http::encode_b64(registration_finish.message.serialize().as_slice()),
            },
        )
        .await
}

pub async fn login(
    client: &PublicHttpClient,
    email: &str,
    password: &[u8],
    device_id: uuid::Uuid,
) -> Result<OpaqueLoginFinishResponse, CliError> {
    let login_start = ClientLogin::<crate::OpaqueCipherSuite>::start(&mut OsRng, password)
        .map_err(|_| CliError::Opaque("login start failed"))?;
    let start_response: OpaqueLoginStartResponse = client
        .post(
            "/api/v1/auth/login/start",
            &OpaqueLoginStartRequest {
                protocol_version: PROTOCOL_VERSION,
                email: email.to_owned(),
                credential_request: crate::http::encode_b64(login_start.message.serialize().as_slice()),
            },
        )
        .await?;
    let credential_response = CredentialResponse::<crate::OpaqueCipherSuite>::deserialize(
        &crate::http::decode_b64(&start_response.credential_response)?,
    )
    .map_err(|_| CliError::Opaque("invalid credential response"))?;
    let login_finish = login_start
        .state
        .finish(
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| CliError::Opaque("login finish failed"))?;

    client
        .post(
            "/api/v1/auth/login/finish",
            &OpaqueLoginFinishRequest {
                protocol_version: PROTOCOL_VERSION,
                login_id: start_response.login_id,
                device_id: Some(device_id),
                credential_finalization: crate::http::encode_b64(login_finish.message.serialize().as_slice()),
            },
        )
        .await
}
```

If OPAQUE method signatures differ from this crate version, adapt to the existing server test client code in `crates/umbra-server/src/tests.rs`.

- [ ] **Step 5: Add public HTTP client and base64 helpers**

In `crates/umbra-cli/src/http.rs`, expose:

```rust
pub struct PublicHttpClient {
    base_url: String,
    inner: reqwest::Client,
}
```

with unauthenticated `post<T, R>`.

Expose:

```rust
pub fn encode_b64(bytes: &[u8]) -> String
pub fn decode_b64(value: &str) -> Result<Vec<u8>, CliError>
```

using `base64ct`.

- [ ] **Step 6: Add password/device prompts**

In `crates/umbra-cli/src/commands.rs`, for `Register`:

```rust
let password = rpassword::prompt_password("Master password: ")?;
let confirm = rpassword::prompt_password("Confirm master password: ")?;
if password != confirm {
    return Err(CliError::Input("passwords do not match"));
}
let device_name = dialoguer::Input::<String>::new()
    .with_prompt("Device name")
    .default("CLI device".to_owned())
    .interact_text()?;
```

Generate device key, call OPAQUE register, store:

```rust
profile.server_url = server;
profile.user_id = Some(response.user_id);
profile.device_id = Some(response.device_id);
profile.device_private_key = Some(device_key.to_base64url());
profile.session_id = None;
profile.legacy_session_token = None;
```

For `Login`, prompt email if not stored in profile by adding `email: Option<String>` to `ProfileConfig`, prompt password, call OPAQUE login, store signed `session_id`.

- [ ] **Step 7: Add dependencies and errors**

In `crates/umbra-cli/Cargo.toml`, add:

```toml
dialoguer = "0.11"
rpassword = "7"
```

In `CliError`, add:

```rust
#[error("opaque error: {0}")]
Opaque(&'static str),
#[error("input error: {0}")]
Input(&'static str),
#[error("prompt error: {0}")]
Prompt(#[from] dialoguer::Error),
#[error("password prompt error: {0}")]
PasswordPrompt(#[from] std::io::Error),
```

If `std::io::Error` already maps to `Io`, do not add a second duplicate `From<std::io::Error>` variant; map prompt errors manually.

- [ ] **Step 8: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli Cargo.toml Cargo.lock
git commit -m "feat(cli): add opaque register and login"
```

---

### Task 8: Add Friendly Vault And Sync Sugar

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Create: `crates/umbra-cli/src/output.rs`

- [ ] **Step 1: Add parser tests for sugar commands**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_sugar_commands() {
    let vault = Cli::parse_from(["umbra", "vault", "create"]);
    assert!(matches!(vault.command, Command::Vault(VaultCommand::Create { name: None })));

    let sync = Cli::parse_from(["umbra", "sync", "--vault", "00000000-0000-0000-0000-000000000001"]);
    assert!(matches!(sync.command, Command::Sync(SyncCommand::Run { .. })));
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test -p umbra-cli parses_sugar_commands
```

Expected: fail because current `vault create` requires name and sync uses `--vault-id`.

- [ ] **Step 3: Make vault create interactive**

Change `VaultCommand::Create`:

```rust
Create {
    name: Option<String>,
    #[arg(long)]
    wrapping_json: Option<String>,
}
```

In command handler:

```rust
let name = match name {
    Some(name) => name,
    None => dialoguer::Input::<String>::new()
        .with_prompt("Vault name")
        .interact_text()?,
};
let wrapping_json = match wrapping_json {
    Some(value) => value,
    None => dialoguer::Input::<String>::new()
        .with_prompt("Initial vault key wrapping JSON")
        .interact_text()?,
};
```

- [ ] **Step 4: Make sync command friendlier**

Change `SyncCommand::Run` args:

```rust
#[arg(long = "vault", alias = "vault-id")]
vault_id: VaultId,
```

In `Command`, add alias:

```rust
#[command(subcommand, alias = "s")]
Sync(SyncCommand),
```

- [ ] **Step 5: Add output helpers**

Create `crates/umbra-cli/src/output.rs`:

```rust
use serde::Serialize;

use crate::error::CliError;

pub fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
```

Replace repeated `println!("{}", serde_json::to_string_pretty(...)?);` with `print_json`.

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets -- -D warnings
cargo fmt --all
```

Expected: pass.

Commit:

```bash
git add crates/umbra-cli/src
git commit -m "feat(cli): add interactive vault and sync sugar"
```

---

### Task 9: Update Docs And Threat Model

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol.md`
- Modify: `docs/threat-model.md`

- [ ] **Step 1: Update README CLI section**

Replace the remote CLI MVP section with:

~~~markdown
## Remote CLI MVP

Register a profile:

```bash
umbra register \
  --server http://127.0.0.1:8080 \
  --email miguel@example.com \
  --profile personal
```

Login:

```bash
umbra login --profile personal
```

Switch profiles:

```bash
umbra profile list
umbra profile use personal
```

Create a personal vault interactively:

```bash
umbra vault create
```

Create an encrypted item envelope:

```bash
umbra item create \
  --vault-id "$VAULT_ID" \
  --kind api_key \
  --envelope-json '{"version":1,"suite":"UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1","ciphertext":"example"}'
```

Sync:

```bash
umbra sync --vault "$VAULT_ID"
```

The CLI uses signed HTTP sessions by default. It does not send reusable bearer tokens for normal login sessions.
~~~

- [ ] **Step 2: Document signed HTTP protocol**

Append to `docs/protocol.md`:

~~~markdown
## Signed HTTP Sessions

For CLI sessions, Umbra can authenticate requests without sending a reusable bearer token.

Each protected request includes:

```http
Umbra-Session-Id: <uuid>
Umbra-Device-Id: <uuid>
Umbra-Timestamp: <unix timestamp>
Umbra-Nonce: <random nonce>
Umbra-Body-Sha256: <base64url sha256 body>
Umbra-Signature: <base64url ed25519 signature>
```

The signature covers:

```txt
UMBRA-SIGNED-REQUEST-V1
METHOD
PATH_AND_QUERY
BODY_SHA256
TIMESTAMP_UNIX
NONCE
SESSION_ID
DEVICE_ID
```

The server rejects stale timestamps and repeated `(session_id, nonce)` pairs.
~~~

- [ ] **Step 3: Document HTTP limitations**

Append to `docs/threat-model.md`:

~~~markdown
## Plain HTTP With Signed Requests

Signed requests avoid sending reusable bearer tokens over plain HTTP and prevent basic replay.

They do not hide:

- host/path;
- IP addresses;
- timing;
- request and response sizes;
- vault ids, item ids, and other metadata present outside encrypted envelopes;
- ciphertexts.

They also do not solve first-contact active MITM by themselves. Production deployments should still prefer HTTPS. Plain HTTP with signed requests is mainly useful for local networks, development, and self-hosted environments where the operator accepts metadata exposure but does not want bearer tokens to leak.
~~~

- [ ] **Step 4: Run checks and commit**

Run:

```bash
cargo fmt --all --check
cargo test --all
```

Expected: pass.

Commit:

```bash
git add README.md docs/protocol.md docs/threat-model.md
git commit -m "docs: document signed HTTP CLI sessions"
```

---

### Task 10: Final Verification And Push

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

- [ ] **Step 2: Inspect status**

Run:

```bash
git status --short
git log --oneline -10
```

Expected: clean working tree and commits for auth crate, storage signed sessions, protocol, server, CLI profiles, CLI login, CLI sugar, docs.

- [ ] **Step 3: Push and watch CI**

Run:

```bash
git push origin main
gh run list --limit 3
gh run watch <new-run-id> --exit-status
```

Expected: CI passes formatting, tests with Postgres, build, and clippy.

---

## Self-Review

Spec coverage:

- No HTTPS bearer-token leak: covered by signed sessions and CLI defaulting to request signatures.
- CLI login: covered by `umbra register` and `umbra login`.
- Multiple logins/accounts: covered by profile-based config and `profile list/use`.
- More usable commands: covered by top-level register/login, interactive `vault create`, and `sync --vault`.
- TUI-style prompt: covered with `dialoguer` interactive prompts, not a full-screen TUI.

Known gaps intentionally left for later:

- item plaintext encryption/decryption UX;
- encrypted local cache;
- OS keychain;
- server identity pinning;
- full ratatui TUI;
- HTTP metadata confidentiality.

Placeholder scan:

- No task uses placeholder markers.
- Each code task has concrete file paths, exact structs/functions, and commands.

Type consistency:

- Signed request fields use `uuid::Uuid` for `session_id` and `device_id`.
- Protocol uses `Option<String>` for legacy bearer token so signed sessions can omit it.
- CLI profile stores `session_id`, `device_id`, and `device_private_key` for signed requests.
