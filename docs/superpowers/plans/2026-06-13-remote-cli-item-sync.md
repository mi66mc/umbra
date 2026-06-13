# Remote CLI Item Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first usable remote Umbra flow: authenticated users can create encrypted item revisions, sync encrypted vault changes, and drive those APIs from a real CLI instead of a placeholder.

**Architecture:** Keep the zero-knowledge boundary intact: the server stores and syncs envelopes only, while CLI commands submit opaque JSON envelopes for this phase. `umbra-protocol` defines typed API contracts, `umbra-server` maps those contracts to `umbra-storage`, and `umbra-cli` becomes a thin remote client with local config for `server_url` and session token.

**Tech Stack:** Rust 1.88, Axum, SQLx/PostgreSQL, Clap, Reqwest, Tokio, Serde/JSON, existing Umbra protocol/storage/server crates.

---

## Current State And Gaps

The repo is modular enough after the last refactor:

- `umbra-core`: good base types, roles, item plaintext schema, validation.
- `umbra-crypto`: good crypto primitives for account keys, user keys, vault key wrapping, item encryption.
- `umbra-protocol`: has auth/org/vault/rotation request types, but sync uses weak `serde_json::Value` arrays and lacks item response DTOs.
- `umbra-storage`: has item revision persistence and key wrapping persistence.
- `umbra-server`: has OPAQUE auth, orgs, vaults, membership, key rotation, but no item or sync HTTP endpoints.
- `umbra-cli`: currently only prints `umbra cli placeholder`.
- Frontend: intentionally absent; do not start it until CLI/server prove the flow.

The next feature should not be frontend. The missing product path is remote CLI + item/sync API. Frontend after this can call the same protocol.

## File Structure

Create or modify these files:

- Modify `crates/umbra-protocol/src/lib.rs`: add typed `ItemRevisionResponse`, `VaultKeyWrappingResponse`, and make `SyncResponse` use typed changes.
- Modify `crates/umbra-protocol/Cargo.toml`: no new dependency required.
- Modify `crates/umbra-storage/src/vaults.rs`: add a helper to list active key wrappings visible to a user during sync if existing method is insufficient.
- Modify `crates/umbra-storage/src/models.rs`: no model shape change expected unless a storage helper needs a new input/output struct.
- Modify `crates/umbra-storage/src/tests.rs`: add database coverage for item revision sync queries.
- Modify `crates/umbra-server/src/authz.rs`: add `ensure_vault_writer`.
- Modify `crates/umbra-server/src/http.rs`: add item and sync routes/handlers plus response mapping helpers.
- Modify `crates/umbra-server/src/tests.rs`: add HTTP integration tests for create item, update item, sync, and viewer write denial.
- Modify `crates/umbra-cli/Cargo.toml`: add CLI runtime dependencies.
- Replace `crates/umbra-cli/src/main.rs`: implement command parsing and remote HTTP client.
- Create `crates/umbra-cli/src/config.rs`: local config load/save.
- Create `crates/umbra-cli/src/error.rs`: CLI error type.
- Create `crates/umbra-cli/src/http.rs`: small reqwest client with bearer auth.
- Create `crates/umbra-cli/src/commands.rs`: command handlers.
- Create `crates/umbra-cli/src/tests.rs`: command parser/config tests.
- Modify `README.md`: document the new remote CLI MVP commands.

## Decisions For This Slice

- CLI auth in this slice uses `umbra auth token set --server-url ... --token ...`.
- Full OPAQUE `umbra auth login` is a separate follow-up. It needs client-side generation/decryption of local user secret, user private key, vault key cache, and secure password prompting.
- Item content in this slice is an envelope JSON supplied by CLI with `--envelope-json`. Client-side encryption UX comes next, using the existing `umbra-crypto`.
- Sync returns item revisions and key wrappings. Deleted item tombstones stay empty until delete support is implemented.
- Server enforces write roles for item create/update. `viewer` can sync/read envelopes but cannot write.

---

### Task 1: Type The Item And Sync Protocol

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`
- Test: `crates/umbra-protocol/src/lib.rs`

- [ ] **Step 1: Write the failing protocol serialization tests**

Add these tests inside the existing `#[cfg(test)] mod tests` in `crates/umbra-protocol/src/lib.rs`. If the file has no test module when this task starts, create one at the bottom and include `use super::*;` inside it:

```rust
use serde_json::json;
use uuid::Uuid;

    #[test]
    fn item_revision_response_roundtrips() {
        let response = ItemRevisionResponse {
            item_id: Uuid::new_v4(),
            vault_id: Uuid::new_v4(),
            revision: 2,
            vault_revision: 7,
            key_generation: 1,
            author_user_id: Some(Uuid::new_v4()),
            envelope: json!({"version": 1, "ciphertext": "abc"}),
        };

        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: ItemRevisionResponse = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, response);
    }

    #[test]
    fn sync_response_uses_typed_changes() {
        let vault_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let response = SyncResponse {
            protocol_version: PROTOCOL_VERSION,
            vaults: vec![VaultSyncChanges {
                vault_id,
                latest_vault_revision: 10,
                items: vec![ItemRevisionResponse {
                    item_id,
                    vault_id,
                    revision: 1,
                    vault_revision: 10,
                    key_generation: 1,
                    author_user_id: Some(user_id),
                    envelope: json!({"ciphertext": "encrypted"}),
                }],
                deleted_items: vec![],
                key_wrappings: vec![VaultKeyWrappingResponse {
                    id: Uuid::new_v4(),
                    vault_id,
                    user_id,
                    device_id: None,
                    wrapping_type: "user_public_key".to_owned(),
                    envelope: json!({"wrapped": true}),
                    key_generation: 1,
                }],
            }],
        };

        let encoded = serde_json::to_value(&response).unwrap();

        assert_eq!(encoded["protocol_version"], json!(1));
        assert_eq!(encoded["vaults"][0]["items"][0]["revision"], json!(1));
        assert_eq!(
            encoded["vaults"][0]["key_wrappings"][0]["wrapping_type"],
            json!("user_public_key")
        );
    }
```

- [ ] **Step 2: Run the protocol tests and verify they fail**

Run:

```bash
cargo test -p umbra-protocol
```

Expected: fail with missing `ItemRevisionResponse` and `VaultKeyWrappingResponse`.

- [ ] **Step 3: Add typed protocol DTOs**

In `crates/umbra-protocol/src/lib.rs`, add these structs after `DeleteItemRequest`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRevisionResponse {
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub revision: RevisionId,
    pub vault_revision: RevisionId,
    pub key_generation: RevisionId,
    pub author_user_id: Option<UserId>,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyWrappingResponse {
    pub id: uuid::Uuid,
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: serde_json::Value,
    pub key_generation: RevisionId,
}
```

Then replace `VaultSyncChanges` with:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSyncChanges {
    pub vault_id: VaultId,
    pub latest_vault_revision: RevisionId,
    pub items: Vec<ItemRevisionResponse>,
    pub deleted_items: Vec<ItemId>,
    pub key_wrappings: Vec<VaultKeyWrappingResponse>,
}
```

- [ ] **Step 4: Run the protocol tests and verify they pass**

Run:

```bash
cargo test -p umbra-protocol
```

Expected: all `umbra-protocol` tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs
git commit -m "feat(protocol): type item sync responses"
```

---

### Task 2: Add Server Authorization For Item Writes

**Files:**
- Modify: `crates/umbra-server/src/authz.rs`
- Test: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Write a failing test for viewer write denial**

Add this helper import to the existing protocol imports in `crates/umbra-server/src/tests.rs`:

```rust
use umbra_core::{VaultKind, VaultRole};
use umbra_protocol::{AddVaultMemberRequest, CreateItemRequest};
```

If `VaultKind` is already imported alone, replace that line with the grouped import above.

Add this test after `opaque_login_token_can_create_org_and_personal_vault`:

```rust
#[tokio::test]
#[serial(postgres)]
async fn viewer_cannot_create_item() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));

    let owner_token = register_and_login(app.clone(), "owner@example.com", b"owner password").await;
    let viewer_token =
        register_and_login(app.clone(), "viewer@example.com", b"viewer password").await;

    let (_status, owner_vault): (StatusCode, VaultResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&owner_token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            name: "Shared".to_owned(),
            kind: VaultKind::Shared,
            initial_key_wrapping: json!({"owner": true}),
        },
    )
    .await;

    let viewer_user_id = login_user_id(app.clone(), "viewer@example.com", b"viewer password").await;
    let (status, _body): (StatusCode, serde_json::Value) = json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/members", owner_vault.vault_id),
        Some(&owner_token),
        &AddVaultMemberRequest {
            protocol_version: PROTOCOL_VERSION,
            user_id: viewer_user_id,
            role: VaultRole::Viewer,
            vault_key_wrapping: json!({"viewer": true}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _body): (StatusCode, serde_json::Value) = json_request(
        app,
        Method::POST,
        &format!("/api/v1/vaults/{}/items", owner_vault.vault_id),
        Some(&viewer_token),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: owner_vault.vault_id,
            kind: umbra_core::ItemKind::ApiKey,
            envelope: json!({"ciphertext": "viewer-write"}),
        },
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}
```

Add this helper below `register_and_login`:

```rust
async fn login_user_id(app: Router, email: &str, password: &[u8]) -> uuid::Uuid {
    let login_start = ClientLogin::<OpaqueCipherSuite>::start(&mut OsRng, password).unwrap();
    let (status, login_response): (StatusCode, OpaqueLoginStartResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/auth/login/start",
        None,
        &OpaqueLoginStartRequest {
            protocol_version: PROTOCOL_VERSION,
            email: email.to_owned(),
            credential_request: encode_b64(login_start.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let credential_response = CredentialResponse::<OpaqueCipherSuite>::deserialize(
        &decode_b64(&login_response.credential_response).unwrap(),
    )
    .unwrap();
    let login_finish = login_start
        .state
        .finish(
            &mut OsRng,
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let (status, finish): (StatusCode, OpaqueLoginFinishResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/auth/login/finish",
        None,
        &OpaqueLoginFinishRequest {
            protocol_version: PROTOCOL_VERSION,
            login_id: login_response.login_id,
            credential_finalization: encode_b64(login_finish.message.serialize().as_slice()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    finish.user_id
}
```

- [ ] **Step 2: Run the server test and verify it fails**

Run:

```bash
cargo test -p umbra-server viewer_cannot_create_item
```

Expected: fail because `/api/v1/vaults/:vault_id/items` does not exist yet.

- [ ] **Step 3: Add `ensure_vault_writer`**

In `crates/umbra-server/src/authz.rs`, add:

```rust
pub(crate) async fn ensure_vault_writer(
    state: &AppState,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<(), ServerError> {
    let members = state.storage.list_vault_members(vault_id).await?;
    let Some(member) = members
        .into_iter()
        .find(|member| member.user_id == user_id && member.state == MemberState::Active)
    else {
        return Err(ServerError::Forbidden);
    };

    if member.role.can_write_items() {
        Ok(())
    } else {
        Err(ServerError::Forbidden)
    }
}
```

- [ ] **Step 4: Run the authz compile check**

Run:

```bash
cargo test -p umbra-server --no-run
```

Expected: compile succeeds or only fails on missing item route from the new test.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-server/src/authz.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): add vault write authorization"
```

---

### Task 3: Add Server Item And Sync Endpoints

**Files:**
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Write the successful item/sync test**

Add these imports in `crates/umbra-server/src/tests.rs`:

```rust
use umbra_protocol::{
    CreateItemRequest, ItemRevisionResponse, SyncRequest, SyncResponse, UpdateItemRequest,
    VaultSyncCursor,
};
```

Add this test after the viewer denial test:

```rust
#[tokio::test]
#[serial(postgres)]
async fn owner_can_create_update_and_sync_item_revisions() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let token = register_and_login(app.clone(), "items@example.com", b"items password").await;

    let (_status, vault): (StatusCode, VaultResponse) = json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            name: "Personal".to_owned(),
            kind: VaultKind::Personal,
            initial_key_wrapping: json!({"wrapped": true}),
        },
    )
    .await;

    let (status, created): (StatusCode, ItemRevisionResponse) = json_request(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{}/items", vault.vault_id),
        Some(&token),
        &CreateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            kind: umbra_core::ItemKind::ApiKey,
            envelope: json!({"ciphertext": "v1"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.revision, 1);
    assert_eq!(created.vault_revision, 1);

    let (status, updated): (StatusCode, ItemRevisionResponse) = json_request(
        app.clone(),
        Method::PUT,
        &format!("/api/v1/vaults/{}/items/{}", vault.vault_id, created.item_id),
        Some(&token),
        &UpdateItemRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            item_id: created.item_id,
            expected_revision: 1,
            envelope: json!({"ciphertext": "v2"}),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated.revision, 2);
    assert_eq!(updated.vault_revision, 2);

    let (status, sync): (StatusCode, SyncResponse) = json_request(
        app,
        Method::POST,
        "/api/v1/sync",
        Some(&token),
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            device_id: uuid::Uuid::new_v4(),
            vaults: vec![VaultSyncCursor {
                vault_id: vault.vault_id,
                since_vault_revision: 0,
            }],
        },
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync.protocol_version, PROTOCOL_VERSION);
    assert_eq!(sync.vaults.len(), 1);
    assert_eq!(sync.vaults[0].latest_vault_revision, 2);
    assert_eq!(sync.vaults[0].items.len(), 2);
    assert_eq!(sync.vaults[0].items[0].envelope, json!({"ciphertext": "v1"}));
    assert_eq!(sync.vaults[0].items[1].envelope, json!({"ciphertext": "v2"}));
    assert_eq!(sync.vaults[0].key_wrappings.len(), 1);
}
```

- [ ] **Step 2: Run the server tests and verify they fail**

Run:

```bash
cargo test -p umbra-server
```

Expected: fail because item/sync routes are missing. Existing unrelated server tests should keep passing.

- [ ] **Step 3: Add routes and imports**

In `crates/umbra-server/src/http.rs`, add these protocol imports:

```rust
CreateItemRequest, ItemRevisionResponse, PROTOCOL_VERSION, SyncRequest, SyncResponse,
UpdateItemRequest, VaultKeyWrappingResponse, VaultSyncChanges,
```

Add these storage imports:

```rust
CreateEncryptedItem, CreateItemRevision,
```

Add `ensure_vault_writer` to the authz import:

```rust
use crate::authz::{
    authenticate, ensure_org_manager, ensure_org_vault_creator, ensure_vault_admin,
    ensure_vault_member, ensure_vault_writer,
};
```

Add these routes inside `router`:

```rust
.route("/api/v1/sync", post(sync))
.route("/api/v1/vaults/:vault_id/items", post(create_item))
.route("/api/v1/vaults/:vault_id/items/:item_id", post(update_item).put(update_item))
```

- [ ] **Step 4: Implement item handlers**

Add these functions before `rotation_status`:

```rust
async fn create_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(request): Json<CreateItemRequest>,
) -> Result<Json<ItemRevisionResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.vault_id != vault_id {
        return Err(ServerError::BadRequest("vault id mismatch"));
    }

    let user_id = authenticate(&state, &headers).await?;
    ensure_vault_writer(&state, vault_id, user_id).await?;

    let revision = state
        .storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id,
            kind: request.kind,
            author_user_id: Some(user_id),
            envelope: request.envelope,
        })
        .await?;

    Ok(Json(item_revision_response(revision)))
}

async fn update_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, item_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateItemRequest>,
) -> Result<Json<ItemRevisionResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    if request.vault_id != vault_id || request.item_id != item_id {
        return Err(ServerError::BadRequest("item path mismatch"));
    }

    let user_id = authenticate(&state, &headers).await?;
    ensure_vault_writer(&state, vault_id, user_id).await?;

    let revision = state
        .storage
        .create_item_revision(CreateItemRevision {
            revision_id: None,
            item_id,
            vault_id,
            expected_revision: request.expected_revision,
            author_user_id: Some(user_id),
            envelope: request.envelope,
        })
        .await?;

    Ok(Json(item_revision_response(revision)))
}
```

- [ ] **Step 5: Implement sync handler**

Add this function before `rotation_status`:

```rust
async fn sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    let user_id = authenticate(&state, &headers).await?;
    let mut vaults = Vec::with_capacity(request.vaults.len());

    for cursor in request.vaults {
        ensure_vault_member(&state, cursor.vault_id, user_id).await?;
        let vault = state.storage.find_vault_by_id(cursor.vault_id).await?;
        let item_revisions = state
            .storage
            .list_item_revisions_since(cursor.vault_id, cursor.since_vault_revision)
            .await?
            .into_iter()
            .map(item_revision_response)
            .collect();
        let key_wrappings = state
            .storage
            .list_key_wrappings_for_user_vault(user_id, cursor.vault_id)
            .await?
            .into_iter()
            .map(vault_key_wrapping_response)
            .collect();

        vaults.push(VaultSyncChanges {
            vault_id: cursor.vault_id,
            latest_vault_revision: vault.vault_revision,
            items: item_revisions,
            deleted_items: vec![],
            key_wrappings,
        });
    }

    Ok(Json(SyncResponse {
        protocol_version: PROTOCOL_VERSION,
        vaults,
    }))
}
```

- [ ] **Step 6: Add response mappers**

Add these helpers near `vault_response`:

```rust
fn item_revision_response(revision: umbra_storage::ItemRevisionRecord) -> ItemRevisionResponse {
    ItemRevisionResponse {
        item_id: revision.item_id,
        vault_id: revision.vault_id,
        revision: revision.revision,
        vault_revision: revision.vault_revision,
        key_generation: revision.key_generation,
        author_user_id: revision.author_user_id,
        envelope: revision.envelope,
    }
}

fn vault_key_wrapping_response(
    wrapping: umbra_storage::VaultKeyWrappingRecord,
) -> VaultKeyWrappingResponse {
    VaultKeyWrappingResponse {
        id: wrapping.id,
        vault_id: wrapping.vault_id,
        user_id: wrapping.user_id,
        device_id: wrapping.device_id,
        wrapping_type: wrapping.wrapping_type,
        envelope: wrapping.envelope,
        key_generation: wrapping.key_generation,
    }
}
```

- [ ] **Step 7: Run server tests**

Run:

```bash
cargo test -p umbra-server
```

Expected: all server tests pass locally. If `UMBRA_TEST_DATABASE_URL` is not set, Postgres tests print skip messages and pass; CI runs them against Postgres.

- [ ] **Step 8: Commit**

```bash
git add crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): add encrypted item sync endpoints"
```

---

### Task 4: Strengthen Storage Sync Coverage

**Files:**
- Modify: `crates/umbra-storage/src/tests.rs`

- [ ] **Step 1: Add storage-level sync cursor assertions**

In `postgres_vault_access_and_rotation_flow`, after the existing `let revisions = storage.list_item_revisions_since(vault.id, 0).await.unwrap();` block, add:

```rust
let later_revisions = storage
    .list_item_revisions_since(vault.id, 1)
    .await
    .unwrap();
assert_eq!(later_revisions.len(), 1);
assert_eq!(later_revisions[0].revision, 2);
assert_eq!(later_revisions[0].envelope, serde_json::json!({"ciphertext": "v2"}));

let current_wrappings = storage
    .list_key_wrappings_for_user_vault(owner.id, vault.id)
    .await
    .unwrap();
assert_eq!(current_wrappings.len(), 1);
assert_eq!(current_wrappings[0].key_generation, 2);
assert_eq!(current_wrappings[0].revoked_at, None);
```

- [ ] **Step 2: Run storage tests**

Run:

```bash
cargo test -p umbra-storage
```

Expected: storage tests pass locally or skip Postgres tests if `UMBRA_TEST_DATABASE_URL` is unset.

- [ ] **Step 3: Commit**

```bash
git add crates/umbra-storage/src/tests.rs
git commit -m "test(storage): cover sync revision queries"
```

---

### Task 5: Replace CLI Placeholder With Remote Command Skeleton

**Files:**
- Modify: `crates/umbra-cli/Cargo.toml`
- Replace: `crates/umbra-cli/src/main.rs`
- Create: `crates/umbra-cli/src/config.rs`
- Create: `crates/umbra-cli/src/error.rs`
- Create: `crates/umbra-cli/src/http.rs`
- Create: `crates/umbra-cli/src/commands.rs`
- Create: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add CLI dependencies**

In `crates/umbra-cli/Cargo.toml`, replace `[dependencies]` with:

```toml
[dependencies]
clap.workspace = true
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio.workspace = true
toml = "0.8"
umbra-core = { path = "../umbra-core" }
umbra-protocol = { path = "../umbra-protocol" }
uuid.workspace = true
```

- [ ] **Step 2: Write CLI parser/config tests**

Create `crates/umbra-cli/src/tests.rs`:

```rust
use clap::Parser;

use crate::config::CliConfig;
use crate::{Cli, Command};

#[test]
fn parses_token_set_command() {
    let cli = Cli::parse_from([
        "umbra",
        "auth",
        "token",
        "set",
        "--server-url",
        "http://localhost:8080",
        "--token",
        "abc",
    ]);

    match cli.command {
        Command::Auth(auth) => {
            assert_eq!(format!("{auth:?}").contains("Token"), true);
        }
        _ => panic!("expected auth command"),
    }
}

#[test]
fn config_roundtrips_toml() {
    let config = CliConfig {
        server_url: "http://localhost:8080".to_owned(),
        session_token: Some("abc".to_owned()),
    };

    let encoded = toml::to_string(&config).unwrap();
    let decoded: CliConfig = toml::from_str(&encoded).unwrap();

    assert_eq!(decoded.server_url, "http://localhost:8080");
    assert_eq!(decoded.session_token.as_deref(), Some("abc"));
}
```

- [ ] **Step 3: Run CLI tests and verify they fail**

Run:

```bash
cargo test -p umbra-cli
```

Expected: fail because CLI types/modules do not exist.

- [ ] **Step 4: Implement CLI error**

Create `crates/umbra-cli/src/error.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("toml encode error: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("missing session token; run `umbra auth token set --server-url <url> --token <token>`")]
    MissingSessionToken,
    #[error("server returned {status}: {body}")]
    ServerStatus { status: reqwest::StatusCode, body: String },
}
```

- [ ] **Step 5: Implement CLI config**

Create `crates/umbra-cli/src/config.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("XDG_CONFIG_HOME").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("umbra").join("config.toml")
}

pub fn load_config() -> Result<CliConfig, CliError> {
    let path = config_path();
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let bytes = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&bytes)?)
}

pub fn save_config(config: &CliConfig) -> Result<(), CliError> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, toml::to_string_pretty(config)?)?;
    Ok(())
}
```

- [ ] **Step 6: Implement HTTP client**

Create `crates/umbra-cli/src/http.rs`:

```rust
use serde::{Serialize, de::DeserializeOwned};

use crate::config::CliConfig;
use crate::error::CliError;

#[derive(Clone)]
pub struct UmbraHttpClient {
    base_url: String,
    token: Option<String>,
    inner: reqwest::Client,
}

impl UmbraHttpClient {
    pub fn new(config: &CliConfig) -> Self {
        Self {
            base_url: config.server_url.trim_end_matches('/').to_owned(),
            token: config.session_token.clone(),
            inner: reqwest::Client::new(),
        }
    }

    pub async fn get<R>(&self, path: &str) -> Result<R, CliError>
    where
        R: DeserializeOwned,
    {
        let request = self.inner.get(format!("{}{}", self.base_url, path));
        self.send(request).await
    }

    pub async fn post<T, R>(&self, path: &str, body: &T) -> Result<R, CliError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let request = self.inner.post(format!("{}{}", self.base_url, path)).json(body);
        self.send(request).await
    }

    pub async fn put<T, R>(&self, path: &str, body: &T) -> Result<R, CliError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let request = self.inner.put(format!("{}{}", self.base_url, path)).json(body);
        self.send(request).await
    }

    async fn send<R>(&self, request: reqwest::RequestBuilder) -> Result<R, CliError>
    where
        R: DeserializeOwned,
    {
        let request = if let Some(token) = &self.token {
            request.bearer_auth(token)
        } else {
            request
        };
        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(CliError::ServerStatus { status, body });
        }
        Ok(serde_json::from_str(&body)?)
    }
}
```

- [ ] **Step 7: Implement command handlers**

Create `crates/umbra-cli/src/commands.rs`:

```rust
use serde_json::Value;
use umbra_core::{ItemKind, VaultKind};
use umbra_protocol::{
    CreateItemRequest, CreateVaultRequest, PROTOCOL_VERSION, SyncRequest, SyncResponse,
    UpdateItemRequest, VaultResponse, VaultSyncCursor,
};
use uuid::Uuid;

use crate::config::{CliConfig, save_config};
use crate::error::CliError;
use crate::http::UmbraHttpClient;
use crate::{AuthCommand, Command, ItemCommand, SyncCommand, TokenCommand, VaultCommand};

pub async fn run(command: Command, mut config: CliConfig) -> Result<(), CliError> {
    match command {
        Command::Auth(AuthCommand::Token(TokenCommand::Set { server_url, token })) => {
            config.server_url = server_url;
            config.session_token = Some(token);
            save_config(&config)?;
            println!("token saved");
            Ok(())
        }
        Command::Vault(VaultCommand::List) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config);
            let vaults: Vec<VaultResponse> = client.get("/api/v1/vaults").await?;
            println!("{}", serde_json::to_string_pretty(&vaults)?);
            Ok(())
        }
        Command::Vault(VaultCommand::Create { name, kind, wrapping_json }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config);
            let vault: VaultResponse = client
                .post(
                    "/api/v1/vaults",
                    &CreateVaultRequest {
                        protocol_version: PROTOCOL_VERSION,
                        name,
                        kind,
                        initial_key_wrapping: serde_json::from_str(&wrapping_json)?,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&vault)?);
            Ok(())
        }
        Command::Item(ItemCommand::Create {
            vault_id,
            kind,
            envelope_json,
        }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config);
            let response: Value = client
                .post(
                    &format!("/api/v1/vaults/{vault_id}/items"),
                    &CreateItemRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        kind,
                        envelope: serde_json::from_str(&envelope_json)?,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
        Command::Item(ItemCommand::Update {
            vault_id,
            item_id,
            expected_revision,
            envelope_json,
        }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config);
            let response: Value = client
                .put(
                    &format!("/api/v1/vaults/{vault_id}/items/{item_id}"),
                    &UpdateItemRequest {
                        protocol_version: PROTOCOL_VERSION,
                        vault_id,
                        item_id,
                        expected_revision,
                        envelope: serde_json::from_str(&envelope_json)?,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
        Command::Sync(SyncCommand::Run {
            vault_id,
            since_vault_revision,
        }) => {
            require_token(&config)?;
            let client = UmbraHttpClient::new(&config);
            let response: SyncResponse = client
                .post(
                    "/api/v1/sync",
                    &SyncRequest {
                        protocol_version: PROTOCOL_VERSION,
                        device_id: Uuid::new_v4(),
                        vaults: vec![VaultSyncCursor {
                            vault_id,
                            since_vault_revision,
                        }],
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
    }
}

fn require_token(config: &CliConfig) -> Result<(), CliError> {
    if config.session_token.is_some() {
        Ok(())
    } else {
        Err(CliError::MissingSessionToken)
    }
}

pub fn parse_vault_kind(value: &str) -> Result<VaultKind, String> {
    match value {
        "personal" => Ok(VaultKind::Personal),
        "shared" => Ok(VaultKind::Shared),
        "project" => Ok(VaultKind::Project),
        "org" => Ok(VaultKind::Org),
        _ => Err("expected one of: personal, shared, project, org".to_owned()),
    }
}

pub fn parse_item_kind(value: &str) -> Result<ItemKind, String> {
    match value {
        "login" => Ok(ItemKind::Login),
        "secure_note" => Ok(ItemKind::SecureNote),
        "ssh_key" => Ok(ItemKind::SshKey),
        "api_key" => Ok(ItemKind::ApiKey),
        "token" => Ok(ItemKind::Token),
        "env_var" => Ok(ItemKind::EnvVar),
        "env_bundle" => Ok(ItemKind::EnvBundle),
        "credit_card" => Ok(ItemKind::CreditCard),
        custom if custom.starts_with("custom:") => {
            Ok(ItemKind::Custom(custom.trim_start_matches("custom:").to_owned()))
        }
        _ => Err("expected known kind or custom:<name>".to_owned()),
    }
}
```

- [ ] **Step 8: Implement CLI main**

Replace `crates/umbra-cli/src/main.rs` with:

```rust
mod commands;
mod config;
mod error;
mod http;

#[cfg(test)]
mod tests;

use clap::{Args, Parser, Subcommand};
use umbra_core::{ItemId, ItemKind, RevisionId, VaultId, VaultKind};

use crate::commands::{parse_item_kind, parse_vault_kind};
use crate::config::load_config;
use crate::error::CliError;

#[derive(Debug, Parser)]
#[command(name = "umbra")]
#[command(about = "Umbra command line client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(subcommand)]
    Auth(AuthCommand),
    #[command(subcommand)]
    Vault(VaultCommand),
    #[command(subcommand)]
    Item(ItemCommand),
    #[command(subcommand)]
    Sync(SyncCommand),
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    Set {
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        token: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    List,
    Create {
        name: String,
        #[arg(long, value_parser = parse_vault_kind, default_value = "personal")]
        kind: VaultKind,
        #[arg(long)]
        wrapping_json: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ItemCommand {
    Create {
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long, value_parser = parse_item_kind)]
        kind: ItemKind,
        #[arg(long)]
        envelope_json: String,
    },
    Update {
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long)]
        item_id: ItemId,
        #[arg(long)]
        expected_revision: RevisionId,
        #[arg(long)]
        envelope_json: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    Run {
        #[arg(long)]
        vault_id: VaultId,
        #[arg(long, default_value_t = 0)]
        since_vault_revision: RevisionId,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    let config = load_config()?;
    commands::run(cli.command, config).await
}
```

- [ ] **Step 9: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: CLI tests pass.

- [ ] **Step 10: Commit**

```bash
git add crates/umbra-cli
git commit -m "feat(cli): add remote item and sync commands"
```

---

### Task 6: Document The MVP Remote Flow

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol.md`

- [ ] **Step 1: Add README commands**

Append this section to `README.md`:

```markdown
## Remote CLI MVP

This stage supports a developer remote flow with a pre-existing session token:

```bash
umbra auth token set \
  --server-url http://127.0.0.1:8080 \
  --token "$UMBRA_SESSION_TOKEN"

umbra vault list

umbra vault create Personal \
  --kind personal \
  --wrapping-json '{"version":1,"type":"vault_key_wrapping","ciphertext":"example"}'

umbra item create \
  --vault-id "$VAULT_ID" \
  --kind api_key \
  --envelope-json '{"version":1,"suite":"UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1","ciphertext":"example"}'

umbra sync run \
  --vault-id "$VAULT_ID" \
  --since-vault-revision 0
```

The server still stores only encrypted envelopes. Human-friendly `umbra auth login`, local unlock, vault key cache, and client-side item encryption are the next CLI layer.
```
```

- [ ] **Step 2: Add protocol docs for item/sync**

Append this to `docs/protocol.md`:

```markdown
## Item And Sync API

Items are stored as encrypted revision envelopes. The server validates vault membership and write roles, but never decrypts item envelopes.

```http
POST /api/v1/vaults/:vault_id/items
PUT /api/v1/vaults/:vault_id/items/:item_id
POST /api/v1/sync
```

`POST /api/v1/sync` accepts per-vault cursors:

```json
{
  "protocol_version": 1,
  "device_id": "00000000-0000-0000-0000-000000000000",
  "vaults": [
    {
      "vault_id": "00000000-0000-0000-0000-000000000000",
      "since_vault_revision": 0
    }
  ]
}
```

The response includes typed encrypted item revisions and vault key wrappings:

```json
{
  "protocol_version": 1,
  "vaults": [
    {
      "vault_id": "00000000-0000-0000-0000-000000000000",
      "latest_vault_revision": 2,
      "items": [],
      "deleted_items": [],
      "key_wrappings": []
    }
  ]
}
```
```
```

- [ ] **Step 3: Run doc-neutral checks**

Run:

```bash
cargo fmt --all --check
cargo test --all
```

Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/protocol.md
git commit -m "docs: document remote cli item sync flow"
```

---

### Task 7: Final Verification And Push

**Files:**
- No source changes expected.

- [ ] **Step 1: Run full local verification**

Run:

```bash
cargo fmt --all --check
cargo test --all
cargo build
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

Expected: all commands pass.

- [ ] **Step 2: Inspect final status**

Run:

```bash
git status --short
git log --oneline -5
```

Expected: working tree clean after commits; recent commits show protocol, server, storage test, CLI, docs.

- [ ] **Step 3: Push main**

Run:

```bash
git push origin main
```

Expected: push succeeds.

- [ ] **Step 4: Watch CI**

Run:

```bash
gh run list --limit 3
gh run watch <new-run-id> --exit-status
```

Expected: CI passes formatting, tests with Postgres, build, and clippy.

---

## Self-Review

Spec coverage:

- Multi-vault and roles: covered by vault-scoped item endpoints and `ensure_vault_writer`.
- Server zero-knowledge: covered because API accepts/stores only JSON envelopes; no decrypt function is introduced in server.
- Sync revision model: covered by `SyncRequest`, `VaultSyncCursor`, `latest_vault_revision`, and item revisions from `list_item_revisions_since`.
- CLI: covered as a remote MVP using stored token and JSON envelopes.
- Frontend: intentionally not covered; it should come after this API/CLI flow is stable.
- Client-side encryption UX: intentionally not covered in this slice; next plan should add `umbra auth login`, local unlock/cache, vault key unwrap, and ergonomic `umbra item create` encryption.

Placeholder scan:

- No task uses unspecified paths.
- Each code-changing step includes concrete code.
- Follow-up work is explicitly scoped out rather than hidden as an implementation gap inside a task.

Type consistency:

- `VaultId`, `ItemId`, `RevisionId`, `VaultKind`, and `ItemKind` come from `umbra-core`.
- Protocol responses use `ItemRevisionResponse` and `VaultKeyWrappingResponse`.
- Server mapping functions convert from `umbra_storage::*Record` types into protocol DTOs.
