# CLI Org And Vault Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make organizations and shared vault membership usable from the CLI while preserving the zero-knowledge boundary by wrapping vault keys client-side for added members.

**Architecture:** The server already has org, org-member, vault-member, and vault-key-wrapping storage. This plan adds the missing typed protocol responses and minimal lookup/list endpoints, then exposes them through `umbra org ...` and `umbra vault members/add-member/remove-member`. The CLI resolves a target user public key from the server, unwraps the local vault key, wraps it to the target user's public key locally, and sends only the encrypted wrapping to the server.

**Tech Stack:** Rust, Clap, Axum, serde/serde_json, existing `umbra-core`, `umbra-protocol`, `umbra-server`, `umbra-cli`, `umbra-crypto`, signed HTTP sessions, existing SQLite/Postgres storage.

---

## Scope

This plan implements direct membership management, not email invites. Users must already have Umbra accounts before being added by email or user id.

Included:

- authenticated user lookup by email for public key discovery;
- typed org member and vault member API responses;
- `umbra org list/create/members/add-member`;
- `umbra vault members/add-member/remove-member`;
- org vault creation through `umbra vault create --org-id <id>`;
- client-side vault key wrapping for added vault members;
- docs and tests.

Not included:

- invite emails;
- accepting invites;
- per-device vault key wrappings;
- automatic key rotation after removal;
- UI/frontend.

---

## File Structure

- Modify `crates/umbra-protocol/src/lib.rs`
  - Add request/response DTOs for user lookup, org members, and vault members.
  - Add protocol serialization tests.

- Modify `crates/umbra-server/src/http.rs`
  - Add signed route `POST /api/v1/users/lookup`.
  - Change org member list/add handlers to return typed `OrgMemberResponse`.
  - Add `GET /api/v1/vaults/:vault_id/members`.
  - Change vault member add/remove behavior only where needed for typed responses.

- Modify `crates/umbra-server/src/tests.rs`
  - Add HTTP tests for user lookup and vault member listing.
  - Extend existing shared-vault tests to verify new member gets a key wrapping in sync.

- Modify `crates/umbra-cli/src/main.rs`
  - Add `OrgCommand`.
  - Add `vault create --org-id`.
  - Add `vault members`, `vault add-member`, `vault remove-member`.
  - Add parser tests.

- Modify `crates/umbra-cli/src/commands.rs`
  - Implement org commands.
  - Implement vault member commands.
  - Add helper functions for user lookup, role rendering, target public key parsing, and member vault key wrapping.
  - Add tests for helper behavior and rendering.

- Modify `README.md`, `docs/architecture.md`, `docs/protocol.md`
  - Document the CLI flow and zero-knowledge wrapping behavior.

---

## Task 1: Protocol DTOs For User And Membership APIs

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`

- [ ] **Step 1: Add failing protocol serialization test**

Add this test inside the existing `#[cfg(test)] mod tests` in `crates/umbra-protocol/src/lib.rs`:

```rust
#[test]
fn membership_protocol_types_roundtrip() {
    use serde_json::json;

    let lookup = UserLookupResponse {
        user_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        email: "ana@example.com".to_owned(),
        public_key: "ana-public-key".to_owned(),
    };
    let encoded = serde_json::to_value(&lookup).unwrap();
    assert_eq!(encoded["email"], json!("ana@example.com"));
    assert_eq!(encoded["public_key"], json!("ana-public-key"));

    let org_member = OrgMemberResponse {
        org_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        user_id: lookup.user_id,
        role: OrgRole::Admin,
        state: MemberState::Active,
    };
    let encoded = serde_json::to_value(&org_member).unwrap();
    assert_eq!(encoded["role"], json!("admin"));
    assert_eq!(encoded["state"], json!("active"));

    let vault_member = VaultMemberResponse {
        vault_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
        user_id: lookup.user_id,
        role: VaultRole::Viewer,
        state: MemberState::Active,
    };
    let encoded = serde_json::to_value(&vault_member).unwrap();
    assert_eq!(encoded["role"], json!("viewer"));
    assert_eq!(encoded["state"], json!("active"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-protocol membership_protocol_types_roundtrip
```

Expected: FAIL because `UserLookupResponse`, `OrgMemberResponse`, `VaultMemberResponse`, and possibly `MemberState` imports do not exist in this crate yet.

- [ ] **Step 3: Import `MemberState`**

At the top of `crates/umbra-protocol/src/lib.rs`, change the `umbra_core` import from:

```rust
use umbra_core::{
    DeviceId, DeviceState, ItemId, ItemKind, OrgId, OrgRole, RevisionId, UserId, VaultId,
    VaultKind, VaultRole,
};
```

to:

```rust
use umbra_core::{
    DeviceId, DeviceState, ItemId, ItemKind, MemberState, OrgId, OrgRole, RevisionId, UserId,
    VaultId, VaultKind, VaultRole,
};
```

- [ ] **Step 4: Add DTOs**

Add these structs after `OrgResponse`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserLookupRequest {
    pub protocol_version: u16,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserLookupResponse {
    pub user_id: UserId,
    pub email: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMemberResponse {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: OrgRole,
    pub state: MemberState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberResponse {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
}
```

- [ ] **Step 5: Run protocol tests**

Run:

```bash
cargo test -p umbra-protocol membership_protocol_types_roundtrip
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs
git commit -m "feat(protocol): add membership DTOs"
```

---

## Task 2: Server User Lookup And Typed Member Responses

**Files:**
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Add failing server test for user lookup**

Add this test in `crates/umbra-server/src/tests.rs` near the other signed HTTP tests:

```rust
#[tokio::test]
async fn signed_user_lookup_returns_public_key() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let login = register_and_signed_login(
        app.clone(),
        "lookup-owner@example.com",
        b"lookup owner password",
        "lookup-owner",
    )
    .await;
    let target = register_user_with_device(
        app.clone(),
        "lookup-target@example.com",
        b"lookup target password",
        Some("Lookup Target"),
        "target laptop",
        "target-device-public-key".to_owned(),
        "target-fingerprint".to_owned(),
        "target-public-key".to_owned(),
    )
    .await;

    let (status, response): (StatusCode, umbra_protocol::UserLookupResponse) =
        signed_json_request(
            app,
            Method::POST,
            "/api/v1/users/lookup",
            login.auth("lookup-user"),
            &umbra_protocol::UserLookupRequest {
                protocol_version: PROTOCOL_VERSION,
                email: "lookup-target@example.com".to_owned(),
            },
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response.user_id, target.user_id);
    assert_eq!(response.email, "lookup-target@example.com");
    assert_eq!(response.public_key, "target-public-key");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-server signed_user_lookup_returns_public_key
```

Expected: FAIL with `404 Not Found` or missing protocol type imports.

- [ ] **Step 3: Update server protocol imports**

In `crates/umbra-server/src/http.rs`, extend the `umbra_protocol` import to include:

```rust
OrgMemberResponse, UserLookupRequest, UserLookupResponse, VaultMemberResponse,
```

The import block should contain these names alongside the existing request/response types:

```rust
use umbra_protocol::{
    AddOrgMemberRequest, AddVaultMemberRequest, ApprovalLookupRequest, ApproveDeviceRequest,
    CreateItemRequest, CreateOrgRequest, CreateOrgVaultRequest, CreateVaultRequest,
    DeviceBootstrapResponse, DeviceResponse, ItemRevisionResponse, LoginDeviceTrustState,
    OpaqueLoginFinishRequest, OpaqueLoginFinishResponse, OpaqueLoginStartRequest,
    OpaqueLoginStartResponse, OpaqueRegisterFinishRequest, OpaqueRegisterStartRequest,
    OpaqueRegisterStartResponse, OrgMemberResponse, OrgResponse, PROTOCOL_VERSION,
    PendingDeviceResponse, PendingDeviceSummary, RecoverTrustRequest, RecoverTrustResponse,
    RecoveryChallengeStartRequest, RecoveryChallengeStartResponse, SyncRequest, SyncResponse,
    SyncStatusRequest, SyncStatusResponse, UserLookupRequest, UserLookupResponse,
    VaultKeyWrappingResponse, VaultMemberResponse, VaultResponse, VaultStatus, VaultSyncChanges,
};
```

- [ ] **Step 4: Add user lookup route**

In the protected router in `crates/umbra-server/src/http.rs`, add this route before the org routes:

```rust
.route("/api/v1/users/lookup", post(lookup_user))
```

- [ ] **Step 5: Add response mapping helpers**

Add these helpers near `vault_response` and `vault_key_wrapping_response`:

```rust
fn org_member_response(member: umbra_storage::OrgMemberRecord) -> OrgMemberResponse {
    OrgMemberResponse {
        org_id: member.org_id,
        user_id: member.user_id,
        role: member.role,
        state: member.state,
    }
}

fn vault_member_response(member: umbra_storage::VaultMemberRecord) -> VaultMemberResponse {
    VaultMemberResponse {
        vault_id: member.vault_id,
        user_id: member.user_id,
        role: member.role,
        state: member.state,
    }
}
```

- [ ] **Step 6: Add lookup handler**

Add this handler before `create_org`:

```rust
async fn lookup_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UserLookupRequest>,
) -> Result<Json<UserLookupResponse>, ServerError> {
    ensure_protocol(request.protocol_version)?;
    authenticate_trusted_context(&state, &headers).await?;
    let user = state.storage.find_user_by_email(&request.email).await?;
    Ok(Json(UserLookupResponse {
        user_id: user.id,
        email: user.email,
        public_key: user.public_key,
    }))
}
```

- [ ] **Step 7: Make org member handlers typed**

Replace `list_org_members` return type and body with:

```rust
async fn list_org_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<OrgMemberResponse>>, ServerError> {
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    ensure_org_manager(&state, org_id, user_id).await?;
    let members = state.storage.list_org_members(org_id).await?;
    Ok(Json(members.into_iter().map(org_member_response).collect()))
}
```

Replace `add_org_member` return type and final `Ok(...)` with:

```rust
) -> Result<Json<OrgMemberResponse>, ServerError> {
```

and:

```rust
Ok(Json(org_member_response(member)))
```

- [ ] **Step 8: Add vault member list route**

In the protected router, change the current members route from:

```rust
.route("/api/v1/vaults/:vault_id/members", post(add_vault_member))
```

to:

```rust
.route(
    "/api/v1/vaults/:vault_id/members",
    get(list_vault_members).post(add_vault_member),
)
```

- [ ] **Step 9: Add vault member list handler and typed add response**

Add before `add_vault_member`:

```rust
async fn list_vault_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
) -> Result<Json<Vec<VaultMemberResponse>>, ServerError> {
    let user_id = authenticate_trusted_context(&state, &headers)
        .await?
        .user_id;
    ensure_vault_member(&state, vault_id, user_id).await?;
    let members = state.storage.list_vault_members(vault_id).await?;
    Ok(Json(members.into_iter().map(vault_member_response).collect()))
}
```

Change `add_vault_member` return type to:

```rust
) -> Result<Json<VaultMemberResponse>, ServerError> {
```

and replace its final `Ok(Json(json!(...)))` with:

```rust
Ok(Json(vault_member_response(member)))
```

- [ ] **Step 10: Add failing test for vault members endpoint**

Add this test in `crates/umbra-server/src/tests.rs`:

```rust
#[tokio::test]
async fn vault_members_endpoint_lists_active_members() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let owner = register_and_signed_login(
        app.clone(),
        "vault-members-owner@example.com",
        b"vault members owner",
        "vault-members-owner",
    )
    .await;
    let member = register_user_with_device(
        app.clone(),
        "vault-members-viewer@example.com",
        b"vault members viewer",
        Some("Vault Member Viewer"),
        "viewer laptop",
        "viewer-device-public-key".to_owned(),
        "viewer-fingerprint".to_owned(),
        "viewer-public-key".to_owned(),
    )
    .await;
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap();
    let (_status, vault): (StatusCode, VaultResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        owner.auth("vault-members-create"),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: Some(vault_id),
            name: "Team".to_owned(),
            kind: VaultKind::Shared,
            initial_key_wrapping: json!({"owner": "wrapping"}),
        },
    )
    .await;
    let (status, _added): (StatusCode, umbra_protocol::VaultMemberResponse) =
        signed_json_request(
            app.clone(),
            Method::POST,
            &format!("/api/v1/vaults/{}/members", vault.vault_id),
            owner.auth("vault-members-add"),
            &AddVaultMemberRequest {
                protocol_version: PROTOCOL_VERSION,
                user_id: member.user_id,
                role: VaultRole::Viewer,
                vault_key_wrapping: json!({"viewer": "wrapping"}),
            },
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, members): (StatusCode, Vec<umbra_protocol::VaultMemberResponse>) =
        signed_json_request(
            app,
            Method::GET,
            &format!("/api/v1/vaults/{}/members", vault.vault_id),
            owner.auth("vault-members-list"),
            &json!({}),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|m| m.user_id == owner.user_id && m.role == VaultRole::Owner));
    assert!(members.iter().any(|m| m.user_id == member.user_id && m.role == VaultRole::Viewer));
}
```

- [ ] **Step 11: Run server tests**

Run:

```bash
cargo test -p umbra-server signed_user_lookup_returns_public_key
cargo test -p umbra-server vault_members_endpoint_lists_active_members
```

Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): expose user and member lookup APIs"
```

---

## Task 3: CLI Command Surface For Orgs And Vault Members

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`

- [ ] **Step 1: Add failing parser tests**

Add these tests to the existing `#[cfg(test)] mod tests` in `crates/umbra-cli/src/main.rs`:

```rust
#[test]
fn parses_org_commands() {
    let list = Cli::parse_from(["umbra", "org", "list"]);
    assert!(matches!(list.command, Command::Org(OrgCommand::List)));

    let create = Cli::parse_from(["umbra", "org", "create", "BlackWire"]);
    assert!(matches!(
        create.command,
        Command::Org(OrgCommand::Create { name }) if name == "BlackWire"
    ));

    let org_id = "00000000-0000-0000-0000-000000000001";
    let members = Cli::parse_from(["umbra", "org", "members", org_id]);
    assert!(matches!(
        members.command,
        Command::Org(OrgCommand::Members { org_id: parsed }) if parsed.to_string() == org_id
    ));

    let add = Cli::parse_from([
        "umbra",
        "org",
        "add-member",
        org_id,
        "--email",
        "ana@example.com",
        "--role",
        "admin",
    ]);
    assert!(matches!(
        add.command,
        Command::Org(OrgCommand::AddMember {
            org_id: parsed,
            email,
            user_id: None,
            role: OrgRole::Admin,
        }) if parsed.to_string() == org_id && email.as_deref() == Some("ana@example.com")
    ));
}

#[test]
fn parses_vault_member_commands() {
    let vault_id = "00000000-0000-0000-0000-000000000001";
    let user_id = "00000000-0000-0000-0000-000000000002";

    let create = Cli::parse_from([
        "umbra",
        "vault",
        "create",
        "Platform",
        "--org-id",
        "00000000-0000-0000-0000-000000000003",
    ]);
    assert!(matches!(
        create.command,
        Command::Vault(VaultCommand::Create { org_id: Some(_), .. })
    ));

    let members = Cli::parse_from(["umbra", "vault", "members", "--vault-id", vault_id]);
    assert!(matches!(
        members.command,
        Command::Vault(VaultCommand::Members { vault_id: Some(parsed), vault: None })
            if parsed.to_string() == vault_id
    ));

    let add = Cli::parse_from([
        "umbra",
        "vault",
        "add-member",
        "--vault-id",
        vault_id,
        "--email",
        "ana@example.com",
        "--role",
        "viewer",
    ]);
    assert!(matches!(
        add.command,
        Command::Vault(VaultCommand::AddMember {
            vault_id: Some(parsed),
            vault: None,
            email,
            user_id: None,
            role: VaultRole::Viewer,
        }) if parsed.to_string() == vault_id && email.as_deref() == Some("ana@example.com")
    ));

    let remove = Cli::parse_from([
        "umbra",
        "vault",
        "remove-member",
        "--vault-id",
        vault_id,
        "--user-id",
        user_id,
    ]);
    assert!(matches!(
        remove.command,
        Command::Vault(VaultCommand::RemoveMember {
            vault_id: Some(parsed),
            user_id: parsed_user,
            ..
        }) if parsed.to_string() == vault_id && parsed_user.to_string() == user_id
    ));
}
```

- [ ] **Step 2: Run parser tests to verify they fail**

Run:

```bash
cargo test -p umbra-cli parses_org_commands
cargo test -p umbra-cli parses_vault_member_commands
```

Expected: FAIL because `Command::Org`, `OrgCommand`, and new vault command variants do not exist.

- [ ] **Step 3: Import role types**

At the top of `crates/umbra-cli/src/main.rs`, change:

```rust
use umbra_core::{ItemKind, VaultId};
```

to:

```rust
use umbra_core::{ItemKind, OrgId, OrgRole, UserId, VaultId, VaultRole};
```

- [ ] **Step 4: Add command variant**

In `pub enum Command`, add this variant before `Vault`:

```rust
#[command(subcommand)]
Org(OrgCommand),
```

- [ ] **Step 5: Add `OrgCommand`**

Add after `EmergencyKitCommand`:

```rust
#[derive(Debug, Subcommand)]
pub enum OrgCommand {
    List,
    Create {
        name: String,
    },
    Members {
        org_id: OrgId,
    },
    AddMember {
        org_id: OrgId,
        #[arg(long, conflicts_with = "user_id", required_unless_present = "user_id")]
        email: Option<String>,
        #[arg(long, conflicts_with = "email", required_unless_present = "email")]
        user_id: Option<UserId>,
        #[arg(long, value_parser = parse_org_role)]
        role: OrgRole,
    },
}
```

- [ ] **Step 6: Extend `VaultCommand`**

Replace:

```rust
Create {
    name: Option<String>,
    #[arg(long)]
    wrapping_json: Option<String>,
},
```

with:

```rust
Create {
    name: Option<String>,
    #[arg(long)]
    org_id: Option<OrgId>,
    #[arg(long)]
    wrapping_json: Option<String>,
},
Members {
    #[arg(long)]
    vault_id: Option<VaultId>,
    #[arg(long)]
    vault: Option<String>,
},
AddMember {
    #[arg(long)]
    vault_id: Option<VaultId>,
    #[arg(long)]
    vault: Option<String>,
    #[arg(long, conflicts_with = "user_id", required_unless_present = "user_id")]
    email: Option<String>,
    #[arg(long, conflicts_with = "email", required_unless_present = "email")]
    user_id: Option<UserId>,
    #[arg(long, value_parser = parse_vault_role)]
    role: VaultRole,
},
RemoveMember {
    #[arg(long)]
    vault_id: Option<VaultId>,
    #[arg(long)]
    vault: Option<String>,
    #[arg(long)]
    user_id: UserId,
},
```

- [ ] **Step 7: Add role parsers**

Add these functions near `parse_item_kind`:

```rust
pub fn parse_org_role(value: &str) -> Result<OrgRole, String> {
    match value {
        "owner" => Ok(OrgRole::Owner),
        "admin" => Ok(OrgRole::Admin),
        "member" => Ok(OrgRole::Member),
        _ => Err("expected one of: owner, admin, member".to_owned()),
    }
}

pub fn parse_vault_role(value: &str) -> Result<VaultRole, String> {
    match value {
        "owner" => Ok(VaultRole::Owner),
        "admin" => Ok(VaultRole::Admin),
        "editor" => Ok(VaultRole::Editor),
        "viewer" => Ok(VaultRole::Viewer),
        _ => Err("expected one of: owner, admin, editor, viewer".to_owned()),
    }
}
```

- [ ] **Step 8: Update existing parser tests that destructure `VaultCommand::Create`**

Where tests match `VaultCommand::Create { name, wrapping_json }`, change them to:

```rust
VaultCommand::Create {
    name,
    org_id: None,
    wrapping_json,
}
```

Where tests only check that create exists, use `..`:

```rust
Command::Vault(VaultCommand::Create { .. })
```

- [ ] **Step 9: Run parser tests**

Run:

```bash
cargo test -p umbra-cli parses_org_commands
cargo test -p umbra-cli parses_vault_member_commands
cargo test -p umbra-cli parses_vault_create_without_wrapping_json
cargo test -p umbra-cli parses_vault_create_as_personal_without_kind
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add crates/umbra-cli/src/main.rs
git commit -m "feat(cli): add org and member command surface"
```

---

## Task 4: CLI Org Commands

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add render tests for orgs and members**

Add these tests to `crates/umbra-cli/src/commands.rs`:

```rust
#[test]
fn role_labels_are_stable_for_membership_output() {
    assert_eq!(org_role_label(umbra_core::OrgRole::Owner), "owner");
    assert_eq!(org_role_label(umbra_core::OrgRole::Admin), "admin");
    assert_eq!(org_role_label(umbra_core::OrgRole::Member), "member");
    assert_eq!(vault_role_label(umbra_core::VaultRole::Owner), "owner");
    assert_eq!(vault_role_label(umbra_core::VaultRole::Admin), "admin");
    assert_eq!(vault_role_label(umbra_core::VaultRole::Editor), "editor");
    assert_eq!(vault_role_label(umbra_core::VaultRole::Viewer), "viewer");
}

#[test]
fn resolve_target_user_requires_exactly_one_selector() {
    let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    assert_eq!(
        resolve_target_user_id(Some(user_id), None, None).unwrap(),
        user_id
    );
    assert!(matches!(
        resolve_target_user_id(Some(user_id), Some(user_id), None),
        Err(CliError::Input(_))
    ));
    assert!(matches!(
        resolve_target_user_id(None, None, None),
        Err(CliError::Input(_))
    ));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p umbra-cli role_labels_are_stable_for_membership_output
cargo test -p umbra-cli resolve_target_user_requires_exactly_one_selector
```

Expected: FAIL because helper functions do not exist.

- [ ] **Step 3: Update imports**

In `crates/umbra-cli/src/commands.rs`, change:

```rust
use umbra_core::{ItemKind, ItemPlaintextV1, VaultId, VaultKind};
```

to:

```rust
use umbra_core::{
    ItemKind, ItemPlaintextV1, MemberState, OrgRole, UserId, VaultId, VaultKind, VaultRole,
};
```

Extend the `umbra_protocol` import with:

```rust
AddOrgMemberRequest, CreateOrgRequest, CreateOrgVaultRequest, OrgMemberResponse, OrgResponse,
UserLookupRequest, UserLookupResponse, VaultMemberResponse,
```

Extend the crate command import with `OrgCommand`:

```rust
use crate::{
    AuthCommand, CacheCommand, Command, DeviceCommand, EmergencyKitCommand, ItemCommand,
    OrgCommand, ProfileCommand, SecretCommand, SyncCommand, TokenCommand, VaultCommand,
};
```

- [ ] **Step 4: Add helper functions**

Add near `vault_kind_label`:

```rust
fn org_role_label(role: OrgRole) -> &'static str {
    match role {
        OrgRole::Owner => "owner",
        OrgRole::Admin => "admin",
        OrgRole::Member => "member",
    }
}

fn vault_role_label(role: VaultRole) -> &'static str {
    match role {
        VaultRole::Owner => "owner",
        VaultRole::Admin => "admin",
        VaultRole::Editor => "editor",
        VaultRole::Viewer => "viewer",
    }
}

fn member_state_label(state: MemberState) -> &'static str {
    match state {
        MemberState::Active => "active",
        MemberState::Invited => "invited",
        MemberState::Removed => "removed",
    }
}

fn resolve_target_user_id(
    explicit_user_id: Option<UserId>,
    lookup_user_id: Option<UserId>,
    email: Option<&str>,
) -> Result<UserId, CliError> {
    match (explicit_user_id, lookup_user_id, email) {
        (Some(user_id), None, None) => Ok(user_id),
        (None, Some(user_id), Some(_)) => Ok(user_id),
        (None, None, Some(_)) => Err(CliError::Input("user lookup did not return a user id")),
        (None, None, None) => Err(CliError::Input("pass --email or --user-id")),
        _ => Err(CliError::Input("pass only one of --email or --user-id")),
    }
}
```

- [ ] **Step 5: Add render helpers**

Add near `render_vaults`:

```rust
fn render_orgs(output: OutputMode, orgs: &[OrgResponse]) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(orgs);
    }
    let rows = orgs
        .iter()
        .map(|org| vec![org.name.clone(), org.org_id.to_string()])
        .collect::<Vec<_>>();
    crate::output::print_table(&["name", "org_id"], &rows);
    Ok(())
}

fn render_org_created(output: OutputMode, org: &OrgResponse) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(org);
    }
    crate::output::print_kv(&[
        ("created org", org.name.clone()),
        ("id", org.org_id.to_string()),
    ]);
    Ok(())
}

fn render_org_members(
    output: OutputMode,
    members: &[OrgMemberResponse],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(members);
    }
    let rows = members
        .iter()
        .map(|member| {
            vec![
                member.user_id.to_string(),
                org_role_label(member.role).to_owned(),
                member_state_label(member.state).to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["user_id", "role", "state"], &rows);
    Ok(())
}

fn render_org_member_added(
    output: OutputMode,
    member: &OrgMemberResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(member);
    }
    crate::output::print_kv(&[
        ("org_id", member.org_id.to_string()),
        ("user_id", member.user_id.to_string()),
        ("role", org_role_label(member.role).to_owned()),
        ("state", member_state_label(member.state).to_owned()),
    ]);
    Ok(())
}
```

- [ ] **Step 6: Add user lookup helper**

Add near other HTTP helper functions:

```rust
async fn lookup_user_by_email(
    client: &UmbraHttpClient,
    email: &str,
) -> Result<UserLookupResponse, CliError> {
    client
        .post(
            "/api/v1/users/lookup",
            &UserLookupRequest {
                protocol_version: PROTOCOL_VERSION,
                email: email.to_owned(),
            },
        )
        .await
}
```

- [ ] **Step 7: Implement org command arms**

In the `match command` inside `run`, add these arms before the vault arms:

```rust
Command::Org(OrgCommand::List) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let orgs: Vec<OrgResponse> = client.get("/api/v1/orgs").await?;
    render_orgs(output, &orgs)
}
Command::Org(OrgCommand::Create { name }) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let org: OrgResponse = client
        .post(
            "/api/v1/orgs",
            &CreateOrgRequest {
                protocol_version: PROTOCOL_VERSION,
                name,
            },
        )
        .await?;
    render_org_created(output, &org)
}
Command::Org(OrgCommand::Members { org_id }) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let members: Vec<OrgMemberResponse> =
        client.get(&format!("/api/v1/orgs/{org_id}/members")).await?;
    render_org_members(output, &members)
}
Command::Org(OrgCommand::AddMember {
    org_id,
    email,
    user_id,
    role,
}) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let looked_up = match email.as_deref() {
        Some(email) => Some(lookup_user_by_email(&client, email).await?.user_id),
        None => None,
    };
    let target_user_id = resolve_target_user_id(user_id, looked_up, email.as_deref())?;
    let member: OrgMemberResponse = client
        .post(
            &format!("/api/v1/orgs/{org_id}/members"),
            &AddOrgMemberRequest {
                protocol_version: PROTOCOL_VERSION,
                user_id: target_user_id,
                role,
            },
        )
        .await?;
    render_org_member_added(output, &member)
}
```

- [ ] **Step 8: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli role_labels_are_stable_for_membership_output
cargo test -p umbra-cli resolve_target_user_requires_exactly_one_selector
cargo test -p umbra-cli parses_org_commands
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): implement org commands"
```

---

## Task 5: CLI Org Vault Creation

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add helper test for org vault request path**

Add this test:

```rust
#[test]
fn vault_create_path_uses_org_endpoint_when_org_id_is_present() {
    let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    assert_eq!(vault_create_path(None), "/api/v1/vaults");
    assert_eq!(
        vault_create_path(Some(org_id)),
        "/api/v1/orgs/00000000-0000-0000-0000-000000000001/vaults"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli vault_create_path_uses_org_endpoint_when_org_id_is_present
```

Expected: FAIL because `vault_create_path` does not exist.

- [ ] **Step 3: Add helper**

Add near other small command helpers:

```rust
fn vault_create_path(org_id: Option<uuid::Uuid>) -> String {
    match org_id {
        Some(org_id) => format!("/api/v1/orgs/{org_id}/vaults"),
        None => "/api/v1/vaults".to_owned(),
    }
}
```

- [ ] **Step 4: Update vault create arm pattern**

Change:

```rust
Command::Vault(VaultCommand::Create {
    name,
    wrapping_json,
}) => {
```

to:

```rust
Command::Vault(VaultCommand::Create {
    name,
    org_id,
    wrapping_json,
}) => {
```

- [ ] **Step 5: Choose vault kind based on org**

Inside the vault create arm, before `let requested_vault_id = Uuid::new_v4();`, add:

```rust
let kind = if org_id.is_some() {
    VaultKind::Org
} else {
    VaultKind::Personal
};
```

Then change the request body from:

```rust
kind: VaultKind::Personal,
```

to:

```rust
kind,
```

- [ ] **Step 6: Use org endpoint when needed**

Replace:

```rust
let created: VaultResponse = client
    .post(
        "/api/v1/vaults",
        &CreateVaultRequest {
```

with:

```rust
let created: VaultResponse = if let Some(org_id) = org_id {
    client
        .post(
            &vault_create_path(Some(org_id)),
            &CreateOrgVaultRequest {
                protocol_version: PROTOCOL_VERSION,
                vault_id: Some(requested_vault_id),
                name,
                kind,
                initial_key_wrapping,
            },
        )
        .await?
} else {
    client
        .post(
            &vault_create_path(None),
            &CreateVaultRequest {
```

and close the `else` branch after the existing personal request:

```rust
            },
        )
        .await?
};
```

The result must still be stored in cache:

```rust
cache.upsert_vault(&created)?;
render_vault_created(output, &created)
```

- [ ] **Step 7: Run tests**

Run:

```bash
cargo test -p umbra-cli vault_create_path_uses_org_endpoint_when_org_id_is_present
cargo test -p umbra-cli parses_vault_member_commands
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): create org vaults"
```

---

## Task 6: CLI Vault Member Management With Client-Side Wrapping

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add helper test for member vault key wrapping**

Add this test:

```rust
#[test]
fn member_vault_key_wrapping_roundtrips_for_target_user() {
    let target = generate_user_keypair();
    let vault_key = generate_vault_key();
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

    let wrapping = wrap_vault_key_for_member(&target.public_key, &vault_key, vault_id).unwrap();
    let envelope: VaultKeyWrappingEnvelopeV1 = serde_json::from_value(wrapping).unwrap();
    let aad = AadV1::vault_key_wrapping(vault_id.to_string());
    let opened = unwrap_vault_key(&target.private_key, &aad, &envelope).unwrap();

    assert_eq!(opened, vault_key);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli member_vault_key_wrapping_roundtrips_for_target_user
```

Expected: FAIL because `wrap_vault_key_for_member` does not exist.

- [ ] **Step 3: Add wrapping helper**

Add near `encrypt_item_plaintext`:

```rust
fn wrap_vault_key_for_member(
    recipient_public_key: &UserPublicKey,
    vault_key: &VaultKey,
    vault_id: VaultId,
) -> Result<Value, CliError> {
    let aad = AadV1::vault_key_wrapping(vault_id.to_string());
    let wrapping = wrap_vault_key_for_user(recipient_public_key, vault_key, aad)?;
    serde_json::to_value(wrapping).map_err(CliError::from)
}
```

- [ ] **Step 4: Add vault member render helpers**

Add near `render_org_members`:

```rust
fn render_vault_members(
    output: OutputMode,
    members: &[VaultMemberResponse],
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(members);
    }
    let rows = members
        .iter()
        .map(|member| {
            vec![
                member.user_id.to_string(),
                vault_role_label(member.role).to_owned(),
                member_state_label(member.state).to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    crate::output::print_table(&["user_id", "role", "state"], &rows);
    Ok(())
}

fn render_vault_member_added(
    output: OutputMode,
    member: &VaultMemberResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(member);
    }
    crate::output::print_kv(&[
        ("vault_id", member.vault_id.to_string()),
        ("user_id", member.user_id.to_string()),
        ("role", vault_role_label(member.role).to_owned()),
        ("state", member_state_label(member.state).to_owned()),
    ]);
    Ok(())
}
```

- [ ] **Step 5: Implement `vault members` command arm**

Add this arm before `VaultCommand::Create` or after it:

```rust
Command::Vault(VaultCommand::Members { vault_id, vault }) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id =
        resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
    let client = UmbraHttpClient::new(profile)?;
    let members: Vec<VaultMemberResponse> =
        client.get(&format!("/api/v1/vaults/{vault_id}/members")).await?;
    render_vault_members(output, &members)
}
```

- [ ] **Step 6: Implement `vault add-member` command arm**

Add this arm near other vault arms:

```rust
Command::Vault(VaultCommand::AddMember {
    vault_id,
    vault,
    email,
    user_id,
    role,
}) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id =
        resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
    let client = UmbraHttpClient::new(profile)?;
    let looked_up = match email.as_deref() {
        Some(email) => Some(lookup_user_by_email(&client, email).await?),
        None => None,
    };
    let target_user_id =
        resolve_target_user_id(user_id, looked_up.as_ref().map(|user| user.user_id), email.as_deref())?;
    let target_public_key = match looked_up {
        Some(user) => UserPublicKey::from_base64url(&user.public_key)?,
        None => {
            return Err(CliError::Input(
                "vault add-member requires --email so the CLI can fetch the target public key",
            ));
        }
    };
    let vault_key = unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?;
    let vault_key_wrapping = wrap_vault_key_for_member(&target_public_key, &vault_key, vault_id)?;
    let member: VaultMemberResponse = client
        .post(
            &format!("/api/v1/vaults/{vault_id}/members"),
            &AddVaultMemberRequest {
                protocol_version: PROTOCOL_VERSION,
                user_id: target_user_id,
                role,
                vault_key_wrapping,
            },
        )
        .await?;
    render_vault_member_added(output, &member)
}
```

This intentionally rejects `--user-id` for vault add-member unless a public-key discovery path is added later. Keeping `--user-id` in the parser is still useful for future direct public-key input, but this first usable flow should be email-based.

- [ ] **Step 7: Implement `vault remove-member` command arm**

Add this arm:

```rust
Command::Vault(VaultCommand::RemoveMember {
    vault_id,
    vault,
    user_id,
}) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id =
        resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
    let client = UmbraHttpClient::new(profile)?;
    client
        .delete(&format!("/api/v1/vaults/{vault_id}/members/{user_id}"))
        .await?;
    if output.is_json() {
        print_json(&serde_json::json!({
            "vault_id": vault_id,
            "user_id": user_id,
            "removed": true
        }))
    } else {
        crate::output::print_kv(&[
            ("vault_id", vault_id.to_string()),
            ("removed user", user_id.to_string()),
            ("key rotation needed", "yes".to_owned()),
        ]);
        Ok(())
    }
}
```

Add this method to `UmbraHttpClient` in `crates/umbra-cli/src/http.rs` if it is not already present:

```rust
pub async fn delete(&self, path: &str) -> Result<(), CliError> {
    self.request::<(), serde_json::Value>(reqwest::Method::DELETE, path, None)
        .await
        .map(|_| ())
}
```

If the internal request helper has a different name, implement the public `delete` method with the same behavior: send a signed HTTP `DELETE` request to `path`, accept an empty response body, and return `Ok(())` on a 2xx response.

- [ ] **Step 8: Run targeted CLI tests**

Run:

```bash
cargo test -p umbra-cli member_vault_key_wrapping_roundtrips_for_target_user
cargo test -p umbra-cli parses_vault_member_commands
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/umbra-cli/src/commands.rs crates/umbra-cli/src/http.rs
git commit -m "feat(cli): manage vault members"
```

---

## Task 7: Docs For Org And Shared Vault CLI

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/protocol.md`

- [ ] **Step 1: Update README**

Add this section after the multi-device flow in `README.md`:

````markdown
## Organizations And Shared Vaults

Personal vaults do not need an organization. Use an organization when a team needs shared ownership and org-scoped vaults.

```bash
umbra org create BlackWire
umbra org list
umbra org add-member <org-id> --email ana@example.com --role admin
umbra org members <org-id>

umbra vault create Platform --org-id <org-id>
umbra vault add-member --vault Platform --email ana@example.com --role editor
umbra vault members --vault Platform
```

`vault add-member` resolves the target user's account public key, unwraps the vault key locally, wraps the vault key to that public key, and sends only the encrypted wrapping to the server. The server never receives the vault key in plaintext.

Removing a vault member stops future sync for that user and revokes their active wrapping, but it does not erase secrets already seen. Rotate the vault key and real third-party secrets after sensitive removals.
````

- [ ] **Step 2: Update architecture docs**

Add this paragraph in `docs/architecture.md` under `## Sharing Flow`:

````markdown
The first CLI sharing flow is direct membership, not email invites. The owner/admin runs `vault add-member --email <email> --role <role>`. The CLI asks the server for the target user's account public key, unwraps the current vault key locally, creates a new `user_public_key` wrapping for the target user, and uploads that encrypted wrapping with the membership change. A user can have personal vaults with `org_id = null`; organizations are only needed for team ownership and org-scoped vaults.
````

- [ ] **Step 3: Update protocol docs**

Add this under the API list in `docs/protocol.md`:

````markdown
### User Lookup

```http
POST /api/v1/users/lookup
```

This trusted endpoint returns `user_id`, email, and account public key for an existing user. It exists so a client can encrypt a vault-key wrapping to that user's public key without exposing the vault key to the server.

### Vault Members

```http
GET /api/v1/vaults/:vault_id/members
POST /api/v1/vaults/:vault_id/members
DELETE /api/v1/vaults/:vault_id/members/:user_id
```

`POST` requires `vault_key_wrapping`. The wrapping is produced client-side with the target account public key. The server stores the wrapping and enforces membership/role checks, but cannot decrypt it.
````

- [ ] **Step 4: Run docs-adjacent checks**

Run:

```bash
cargo test -p umbra-cli parses_org_commands
cargo test -p umbra-cli parses_vault_member_commands
cargo test -p umbra-server signed_user_lookup_returns_public_key
cargo test -p umbra-server vault_members_endpoint_lists_active_members
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/architecture.md docs/protocol.md
git commit -m "docs(cli): document org and vault sharing"
```

---

## Task 8: Final Verification

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

- [ ] **Step 4: Inspect commits**

Run:

```bash
git log --oneline origin/main..HEAD
git status --short --branch
```

Expected: new commits are:

```txt
feat(protocol): add membership DTOs
feat(server): expose user and member lookup APIs
feat(cli): add org and member command surface
feat(cli): implement org commands
feat(cli): create org vaults
feat(cli): manage vault members
docs(cli): document org and vault sharing
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

- Users can keep personal vaults without orgs: covered by keeping `vault create` personal by default and adding `--org-id` only when needed.
- Organizations are available from CLI: covered by Task 4.
- Users can be added to orgs: covered by `org add-member`.
- Users can be added to vaults they should access: covered by `vault add-member`.
- Cryptography stays client-side: covered by Task 6 wrapping helper and docs.
- Server never sees plaintext vault key: Task 6 sends only `vault_key_wrapping`.
- Removal exists and documents rotation caveat: Task 6 and Task 7.

Placeholder scan:

- No placeholder language is required for implementation.
- The only adaptation note is for `UmbraHttpClient::delete`, with exact expected public behavior.

Type consistency:

- `UserLookupRequest`, `UserLookupResponse`, `OrgMemberResponse`, and `VaultMemberResponse` are introduced in Task 1 and reused consistently later.
- `OrgCommand` and new `VaultCommand` variants are introduced in Task 3 and implemented in Tasks 4-6.
- Role label/parser names are consistent: `parse_org_role`, `parse_vault_role`, `org_role_label`, `vault_role_label`.
