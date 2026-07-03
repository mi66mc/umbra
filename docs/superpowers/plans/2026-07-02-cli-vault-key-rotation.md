# CLI Vault Key Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a usable zero-knowledge CLI flow to rotate a vault key after member/device removal by rewrapping the new vault key for active members and reencrypting cached item revisions client-side.

**Architecture:** The server already exposes `GET /api/v1/vaults/:vault_id/rotation-status` and `POST /api/v1/vaults/:vault_id/rotate-key`; this plan makes the CLI able to build the `RotateVaultKeyRequest` safely. The server remains a coordinator that stores encrypted wrappings and encrypted item revisions only. Active vault member public keys are exposed in typed member responses so the CLI can encrypt the new vault key for every remaining active member.

**Tech Stack:** Rust, Clap, Axum, serde/serde_json, existing `umbra-core`, `umbra-protocol`, `umbra-server`, `umbra-cli`, `umbra-crypto`, signed HTTP sessions, local SQLite cache.

---

## Scope

Included:

- expose member account public keys in `VaultMemberResponse`;
- add `umbra crypto rotation-status`;
- add `umbra crypto rotate-vault-key`;
- support `--vault-id`, `--vault`, default/interactive vault selection, `--dry-run`, `--force`, and `--yes`;
- generate a fresh random `VaultKey`;
- unwrap the old vault key locally;
- decrypt latest cached item revisions with the old key;
- reencrypt those items with the new key and next item revision number;
- wrap the new vault key for every active vault member using their account public key;
- call `POST /api/v1/vaults/:vault_id/rotate-key`;
- refresh local sync cache and local unlock state after successful rotation;
- document the rotation flow and test the core cryptographic request builder.

Not included:

- per-device vault key wrapping;
- background/automatic rotation;
- invite acceptance;
- rotating real third-party credentials;
- conflict UI for item revisions changed during rotation beyond surfacing server conflict.

---

## File Structure

- Modify `crates/umbra-protocol/src/lib.rs`
  - Add `public_key: String` to `VaultMemberResponse`.
  - Update protocol serialization tests.

- Modify `crates/umbra-server/src/http.rs`
  - Populate `VaultMemberResponse.public_key` from `users.public_key`.
  - Keep org member responses unchanged.

- Modify `crates/umbra-server/src/tests.rs`
  - Assert vault member list/add responses include account public keys.

- Modify `crates/umbra-cli/src/main.rs`
  - Add `CryptoCommand`.
  - Add `crypto rotation-status` and `crypto rotate-vault-key`.

- Modify `crates/umbra-cli/src/commands.rs`
  - Import rotation protocol types.
  - Add pure helpers for building rotation requests.
  - Add render helpers.
  - Implement the two crypto commands.
  - Keep plaintext crypto local to the CLI.

- Modify `crates/umbra-cli/src/tests.rs`
  - Add Clap parser tests for the new crypto commands.

- Modify `README.md`, `docs/architecture.md`, `docs/protocol.md`
  - Document key rotation workflow and server zero-knowledge boundary.

---

## Task 1: Add Member Public Keys To Protocol Responses

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`

- [ ] **Step 1: Update the failing protocol test**

In `crates/umbra-protocol/src/lib.rs`, update the `membership_protocol_types_roundtrip` test's `VaultMemberResponse` construction:

```rust
let vault_member = VaultMemberResponse {
    vault_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
    user_id: lookup.user_id,
    role: VaultRole::Viewer,
    state: MemberState::Active,
    public_key: "ana-public-key".to_owned(),
};
let encoded = serde_json::to_value(&vault_member).unwrap();
assert_eq!(encoded["role"], json!("viewer"));
assert_eq!(encoded["state"], json!("active"));
assert_eq!(encoded["public_key"], json!("ana-public-key"));
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
cargo test -p umbra-protocol membership_protocol_types_roundtrip
```

Expected: FAIL with a missing `public_key` field on `VaultMemberResponse`.

- [ ] **Step 3: Add `public_key` to the DTO**

Change `VaultMemberResponse` to:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberResponse {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
    pub public_key: String,
}
```

- [ ] **Step 4: Run the protocol test**

Run:

```bash
cargo test -p umbra-protocol membership_protocol_types_roundtrip
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs
git commit -m "feat(protocol): include vault member public keys"
```

---

## Task 2: Populate Vault Member Public Keys On The Server

**Files:**
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Update server tests to expect public keys**

In `crates/umbra-server/src/tests.rs`, inside `vault_members_endpoint_lists_active_members`, replace the final member assertions with:

```rust
let owner_member = members
    .iter()
    .find(|m| m.user_id == owner.user_id)
    .expect("owner member is listed");
assert_eq!(owner_member.role, VaultRole::Owner);
assert_eq!(owner_member.public_key, "first-public-key");

let viewer_member = members
    .iter()
    .find(|m| m.user_id == member.user_id)
    .expect("viewer member is listed");
assert_eq!(viewer_member.role, VaultRole::Viewer);
assert_eq!(viewer_member.public_key, "viewer-public-key");
```

In the same test, after the `add_vault_member` request, assert the response public key:

```rust
assert_eq!(_added.public_key, "viewer-public-key");
```

- [ ] **Step 2: Run the server test to verify it fails**

Run:

```bash
cargo test -p umbra-server vault_members_endpoint_lists_active_members
```

Expected: FAIL because the server cannot construct `VaultMemberResponse` without `public_key`.

- [ ] **Step 3: Replace the vault member response helper**

In `crates/umbra-server/src/http.rs`, replace:

```rust
fn vault_member_response(member: umbra_storage::VaultMemberRecord) -> VaultMemberResponse {
    VaultMemberResponse {
        vault_id: member.vault_id,
        user_id: member.user_id,
        role: member.role,
        state: member.state,
    }
}
```

with:

```rust
async fn vault_member_response(
    state: &AppState,
    member: umbra_storage::VaultMemberRecord,
) -> Result<VaultMemberResponse, ServerError> {
    let user = state.storage.find_user_by_id(member.user_id).await?;
    Ok(VaultMemberResponse {
        vault_id: member.vault_id,
        user_id: member.user_id,
        role: member.role,
        state: member.state,
        public_key: user.public_key,
    })
}
```

- [ ] **Step 4: Update `list_vault_members`**

Replace the final body:

```rust
let members = state.storage.list_vault_members(vault_id).await?;
Ok(Json(members.into_iter().map(vault_member_response).collect()))
```

with:

```rust
let members = state.storage.list_vault_members(vault_id).await?;
let mut responses = Vec::with_capacity(members.len());
for member in members {
    responses.push(vault_member_response(&state, member).await?);
}
Ok(Json(responses))
```

- [ ] **Step 5: Update `add_vault_member`**

Replace:

```rust
Ok(Json(vault_member_response(member)))
```

with:

```rust
Ok(Json(vault_member_response(&state, member).await?))
```

- [ ] **Step 6: Run server tests**

Run:

```bash
cargo test -p umbra-server vault_members_endpoint_lists_active_members
cargo test -p umbra-server signed_user_lookup_returns_public_key
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs
git commit -m "feat(server): include public keys in vault members"
```

---

## Task 3: Add CLI Crypto Command Surface

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add failing parser tests**

In `crates/umbra-cli/src/tests.rs`, add `CryptoCommand` to the import list:

```rust
use crate::{
    AuthCommand, CacheCommand, Cli, Command, CryptoCommand, DeviceCommand, ItemCommand,
    ProfileCommand, SecretCommand, TokenCommand, VaultCommand,
};
```

Add these tests:

```rust
#[test]
fn parses_crypto_rotation_commands() {
    let vault_id = "00000000-0000-0000-0000-000000000001";

    let status = Cli::parse_from(["umbra", "crypto", "rotation-status", "--vault-id", vault_id]);
    assert!(matches!(
        status.command,
        Command::Crypto(CryptoCommand::RotationStatus {
            vault_id: Some(parsed),
            vault: None
        }) if parsed.to_string() == vault_id
    ));

    let rotate = Cli::parse_from([
        "umbra",
        "crypto",
        "rotate-vault-key",
        "--vault",
        "Platform",
        "--dry-run",
        "--yes",
    ]);
    assert!(matches!(
        rotate.command,
        Command::Crypto(CryptoCommand::RotateVaultKey {
            vault_id: None,
            vault: Some(name),
            dry_run: true,
            force: false,
            yes: true,
        }) if name == "Platform"
    ));

    let forced = Cli::parse_from([
        "umbra",
        "crypto",
        "rotate-vault-key",
        "--vault-id",
        vault_id,
        "--force",
        "--yes",
    ]);
    assert!(matches!(
        forced.command,
        Command::Crypto(CryptoCommand::RotateVaultKey {
            vault_id: Some(parsed),
            vault: None,
            dry_run: false,
            force: true,
            yes: true,
        }) if parsed.to_string() == vault_id
    ));
}
```

- [ ] **Step 2: Run parser test to verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_crypto_rotation_commands
```

Expected: FAIL because `CryptoCommand` and `Command::Crypto` do not exist.

- [ ] **Step 3: Add `CryptoCommand` to the CLI**

In `crates/umbra-cli/src/main.rs`, add this enum variant to `Command` after `Cache`:

```rust
#[command(subcommand)]
Crypto(CryptoCommand),
```

Add this enum near the other command enums:

```rust
#[derive(Debug, Subcommand)]
pub enum CryptoCommand {
    RotationStatus {
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
    },
    RotateVaultKey {
        #[arg(long)]
        vault_id: Option<VaultId>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        yes: bool,
    },
}
```

- [ ] **Step 4: Wire temporary command arms**

In `crates/umbra-cli/src/commands.rs`, add `CryptoCommand` to the import list:

```rust
use crate::{
    AuthCommand, CacheCommand, Command, CryptoCommand, DeviceCommand, EmergencyKitCommand,
    ItemCommand, OrgCommand, ProfileCommand, SecretCommand, SyncCommand, TokenCommand,
    VaultCommand,
};
```

Add these match arms before `Command::Vault(...)` arms:

```rust
Command::Crypto(CryptoCommand::RotationStatus { .. }) => Err(CliError::Input(
    "crypto rotation-status is not implemented yet",
)),
Command::Crypto(CryptoCommand::RotateVaultKey { .. }) => Err(CliError::Input(
    "crypto rotate-vault-key is not implemented yet",
)),
```

- [ ] **Step 5: Run parser test**

Run:

```bash
cargo test -p umbra-cli parses_crypto_rotation_commands
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/tests.rs crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): add crypto rotation commands"
```

---

## Task 4: Add Pure Rotation Request Builder

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Extend protocol imports**

In `crates/umbra-cli/src/commands.rs`, extend the `umbra_protocol` import with:

```rust
RotateVaultKeyRequest, RotationItemRevision, RotationStatusResponse, RotationVaultKeyWrapping,
```

The import block must include:

```rust
use umbra_protocol::{
    AddOrgMemberRequest, AddVaultMemberRequest, ApprovalLookupRequest, ApproveDeviceRequest,
    CreateItemRequest, CreateOrgRequest, CreateOrgVaultRequest, CreateVaultRequest,
    DeviceBootstrapResponse, DeviceResponse, ItemRevisionResponse, OrgMemberResponse, OrgResponse,
    PROTOCOL_VERSION, PendingDeviceSummary, RecoverTrustRequest, RecoverTrustResponse,
    RecoveryChallengeStartRequest, RecoveryChallengeStartResponse, RotateVaultKeyRequest,
    RotationItemRevision, RotationStatusResponse, RotationVaultKeyWrapping, SyncRequest,
    SyncResponse, UpdateItemRequest, UserLookupRequest, UserLookupResponse, VaultMemberResponse,
    VaultResponse, VaultSyncCursor,
};
```

- [ ] **Step 2: Add failing helper tests**

In the `#[cfg(test)] mod tests` at the bottom of `crates/umbra-cli/src/commands.rs`, add:

```rust
#[test]
fn rotation_next_generation_rejects_invalid_current_generation() {
    assert!(rotation_next_generation(0).is_err());
    assert!(rotation_next_generation(-1).is_err());
    assert_eq!(rotation_next_generation(1).unwrap(), 2);
}

#[test]
fn build_rotation_request_rewraps_members_and_reencrypts_items() {
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let member_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let old_vault_key = generate_vault_key();
    let new_vault_key = generate_vault_key();
    let member_keys = generate_user_keypair();
    let plaintext = ItemPlaintextV1 {
        schema_version: 1,
        title: "GitHub".to_owned(),
        fields: vec![],
        notes: Some("rotated".to_owned()),
        tags: vec![],
    };
    let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let envelope = encrypt_item_plaintext(
        vault_id,
        item_id,
        1,
        "login".to_owned(),
        &old_vault_key,
        &plaintext,
    )
    .unwrap();
    let revision = crate::cache::CachedItemRevision {
        vault_id,
        item_id,
        revision: 1,
        vault_revision: 1,
        key_generation: 1,
        author_user_id: None,
        envelope,
    };
    let member = VaultMemberResponse {
        vault_id,
        user_id: member_id,
        role: VaultRole::Editor,
        state: MemberState::Active,
        public_key: member_keys.public_key.to_base64url(),
    };

    let request = build_rotation_request(
        vault_id,
        1,
        &old_vault_key,
        &new_vault_key,
        &[member],
        &[revision],
    )
    .unwrap();

    assert_eq!(request.from_generation, 1);
    assert_eq!(request.to_generation, 2);
    assert_eq!(request.new_wrappings.len(), 1);
    assert_eq!(request.new_wrappings[0].user_id, member_id);
    assert_eq!(request.new_wrappings[0].wrapping_type, "user_public_key");
    assert_eq!(request.reencrypted_revisions.len(), 1);
    assert_eq!(request.reencrypted_revisions[0].expected_revision, 1);

    let wrapping: VaultKeyWrappingEnvelopeV1 =
        serde_json::from_value(request.new_wrappings[0].envelope.clone()).unwrap();
    let wrapping_aad = AadV1::vault_key_wrapping(vault_id.to_string());
    let opened = unwrap_vault_key(&member_keys.private_key, &wrapping_aad, &wrapping).unwrap();
    assert_eq!(opened, new_vault_key);

    let wrapper: ItemEnvelopeWrapper =
        serde_json::from_value(request.reencrypted_revisions[0].envelope.clone()).unwrap();
    let item_aad = AadV1::item(vault_id.to_string(), item_id.to_string(), 2, "login");
    let decrypted = decrypt_item(&new_vault_key, &item_aad, &wrapper.crypto).unwrap();
    let rotated_plaintext: ItemPlaintextV1 = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(rotated_plaintext.title, "GitHub");
}
```

- [ ] **Step 3: Run helper tests to verify they fail**

Run:

```bash
cargo test -p umbra-cli rotation_next_generation_rejects_invalid_current_generation
cargo test -p umbra-cli build_rotation_request_rewraps_members_and_reencrypts_items
```

Expected: FAIL because the helper functions do not exist and `DecryptedCachedItem` does not expose item kind.

- [ ] **Step 4: Preserve item kind during decrypt**

Change:

```rust
struct DecryptedCachedItem {
    plaintext: ItemPlaintextV1,
}
```

to:

```rust
struct DecryptedCachedItem {
    kind: String,
    plaintext: ItemPlaintextV1,
}
```

Change `decrypt_cached_item_wrapper` final return from:

```rust
Ok(DecryptedCachedItem {
    plaintext: serde_json::from_slice(&plaintext)?,
})
```

to:

```rust
Ok(DecryptedCachedItem {
    kind: wrapper.kind,
    plaintext: serde_json::from_slice(&plaintext)?,
})
```

- [ ] **Step 5: Add rotation helper structs and functions**

Add these helpers near `wrap_vault_key_for_member`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RotationPlanSummary {
    vault_id: VaultId,
    from_generation: i64,
    to_generation: i64,
    member_wrapping_count: usize,
    item_revision_count: usize,
    dry_run: bool,
}

fn rotation_next_generation(current_key_generation: i64) -> Result<i64, CliError> {
    if current_key_generation < 1 {
        return Err(CliError::Input("current key generation must be positive"));
    }
    Ok(current_key_generation + 1)
}

fn build_rotation_request(
    vault_id: VaultId,
    from_generation: i64,
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    members: &[VaultMemberResponse],
    current_revisions: &[crate::cache::CachedItemRevision],
) -> Result<RotateVaultKeyRequest, CliError> {
    let to_generation = rotation_next_generation(from_generation)?;
    let active_members = members
        .iter()
        .filter(|member| member.state == MemberState::Active)
        .collect::<Vec<_>>();
    if active_members.is_empty() {
        return Err(CliError::Input("cannot rotate a vault with no active members"));
    }

    let mut new_wrappings = Vec::with_capacity(active_members.len());
    for member in active_members {
        let public_key = UserPublicKey::from_base64url(&member.public_key)?;
        new_wrappings.push(RotationVaultKeyWrapping {
            user_id: member.user_id,
            device_id: None,
            wrapping_type: "user_public_key".to_owned(),
            envelope: wrap_vault_key_for_member(&public_key, new_vault_key, vault_id)?,
        });
    }

    let mut reencrypted_revisions = Vec::with_capacity(current_revisions.len());
    for revision in current_revisions {
        if revision.key_generation != from_generation {
            return Err(CliError::Input(
                "cached item generation is stale; run `umbra sync run --force-full` and try again",
            ));
        }
        let decrypted = decrypt_cached_item(old_vault_key, revision)?;
        let next_revision = revision.revision + 1;
        let envelope = encrypt_item_plaintext(
            vault_id,
            revision.item_id,
            next_revision,
            decrypted.kind,
            new_vault_key,
            &decrypted.plaintext,
        )?;
        reencrypted_revisions.push(RotationItemRevision {
            item_id: revision.item_id,
            expected_revision: revision.revision,
            envelope,
        });
    }

    Ok(RotateVaultKeyRequest {
        protocol_version: PROTOCOL_VERSION,
        from_generation,
        to_generation,
        new_wrappings,
        reencrypted_revisions,
    })
}
```

- [ ] **Step 6: Run helper tests**

Run:

```bash
cargo test -p umbra-cli rotation_next_generation_rejects_invalid_current_generation
cargo test -p umbra-cli build_rotation_request_rewraps_members_and_reencrypts_items
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): build vault rotation requests"
```

---

## Task 5: Implement CLI Rotation Commands

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Add render and unlock-store helpers**

Add these helpers near the other render helpers:

```rust
fn render_rotation_status(
    output: OutputMode,
    status: &RotationStatusResponse,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(status);
    }
    crate::output::print_kv(&[
        ("vault_id", status.vault_id.to_string()),
        ("current key generation", status.current_key_generation.to_string()),
        (
            "needs key rotation",
            if status.needs_key_rotation { "yes" } else { "no" }.to_owned(),
        ),
    ]);
    Ok(())
}

fn render_rotation_complete(
    output: OutputMode,
    status: &RotationStatusResponse,
    summary: &RotationPlanSummary,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(&serde_json::json!({
            "status": status,
            "summary": summary,
        }));
    }
    crate::output::print_kv(&[
        ("vault_id", status.vault_id.to_string()),
        ("from generation", summary.from_generation.to_string()),
        ("to generation", summary.to_generation.to_string()),
        ("member wrappings", summary.member_wrapping_count.to_string()),
        ("reencrypted items", summary.item_revision_count.to_string()),
        (
            "needs key rotation",
            if status.needs_key_rotation { "yes" } else { "no" }.to_owned(),
        ),
    ]);
    Ok(())
}

fn render_rotation_dry_run(
    output: OutputMode,
    summary: &RotationPlanSummary,
) -> Result<(), CliError> {
    if output.is_json() {
        return print_json(summary);
    }
    crate::output::print_kv(&[
        ("vault_id", summary.vault_id.to_string()),
        ("from generation", summary.from_generation.to_string()),
        ("to generation", summary.to_generation.to_string()),
        ("member wrappings", summary.member_wrapping_count.to_string()),
        ("items to reencrypt", summary.item_revision_count.to_string()),
        ("dry run", "yes".to_owned()),
    ]);
    Ok(())
}

fn save_rotated_vault_key_to_unlock_store(
    profile_name: &str,
    profile: &crate::config::ProfileConfig,
    vault_id: VaultId,
    new_vault_key: VaultKey,
) -> Result<(), CliError> {
    let Some(mut state) =
        crate::unlock_store::UnlockStore::open(profile_name, profile.device_id).load()?
    else {
        return Ok(());
    };
    state.vault_keys.insert(vault_id, new_vault_key);
    crate::unlock_store::UnlockStore::open(profile_name, profile.device_id).save(&state)
}
```

- [ ] **Step 2: Replace temporary `rotation-status` arm**

Replace:

```rust
Command::Crypto(CryptoCommand::RotationStatus { .. }) => Err(CliError::Input(
    "crypto rotation-status is not implemented yet",
)),
```

with:

```rust
Command::Crypto(CryptoCommand::RotationStatus { vault_id, vault }) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let vault_id =
        resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;
    let client = UmbraHttpClient::new(profile)?;
    let status: RotationStatusResponse = client
        .get(&format!("/api/v1/vaults/{vault_id}/rotation-status"))
        .await?;
    render_rotation_status(output, &status)
}
```

- [ ] **Step 3: Replace temporary `rotate-vault-key` arm**

Replace:

```rust
Command::Crypto(CryptoCommand::RotateVaultKey { .. }) => Err(CliError::Input(
    "crypto rotate-vault-key is not implemented yet",
)),
```

with:

```rust
Command::Crypto(CryptoCommand::RotateVaultKey {
    vault_id,
    vault,
    dry_run,
    force,
    yes,
}) => {
    let profile_name = config.active_profile.clone();
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let mut cache = crate::cache::LocalCache::open(&profile_name)?;
    let vault_id =
        resolve_vault_id_for_output(profile, &cache, vault_id, vault.as_deref(), output)?;

    let status: RotationStatusResponse = client
        .get(&format!("/api/v1/vaults/{vault_id}/rotation-status"))
        .await?;
    if !status.needs_key_rotation && !force {
        return Err(CliError::Input(
            "vault does not require rotation; pass --force to rotate anyway",
        ));
    }
    if !dry_run && !yes && output.is_json() {
        return Err(CliError::Input("pass --yes to rotate vault key in JSON mode"));
    }
    if !dry_run && !yes {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt("Rotate this vault key and reencrypt all cached items?")
            .default(false)
            .interact()?;
        if !confirmed {
            return Err(CliError::Input("vault key rotation cancelled"));
        }
    }

    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        vault_id,
        crate::sync::SyncMode::IfChanged,
    )
    .await?;
    let members: Vec<VaultMemberResponse> =
        client.get(&format!("/api/v1/vaults/{vault_id}/members")).await?;
    let current_revisions = cache.list_latest_item_revisions(vault_id)?;
    let old_vault_key = unlock_vault_key(&profile_name, profile, &cache, vault_id)?;
    let new_vault_key = generate_vault_key();
    let request = build_rotation_request(
        vault_id,
        status.current_key_generation,
        &old_vault_key,
        &new_vault_key,
        &members,
        &current_revisions,
    )?;
    let summary = RotationPlanSummary {
        vault_id,
        from_generation: request.from_generation,
        to_generation: request.to_generation,
        member_wrapping_count: request.new_wrappings.len(),
        item_revision_count: request.reencrypted_revisions.len(),
        dry_run,
    };
    if dry_run {
        return render_rotation_dry_run(output, &summary);
    }

    let rotated: RotationStatusResponse = client
        .post(&format!("/api/v1/vaults/{vault_id}/rotate-key"), &request)
        .await?;
    save_rotated_vault_key_to_unlock_store(&profile_name, profile, vault_id, new_vault_key)?;
    crate::sync::ensure_vault_synced(
        profile,
        &mut cache,
        vault_id,
        crate::sync::SyncMode::Always,
    )
    .await?;
    render_rotation_complete(output, &rotated, &summary)
}
```

- [ ] **Step 4: Run targeted CLI tests**

Run:

```bash
cargo test -p umbra-cli parses_crypto_rotation_commands
cargo test -p umbra-cli build_rotation_request_rewraps_members_and_reencrypts_items
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): rotate vault keys"
```

---

## Task 6: Add Server Integration Coverage For Rotation Endpoint Shape

**Files:**
- Modify: `crates/umbra-server/src/tests.rs`

- [ ] **Step 1: Add a server test for rotation with active member public keys**

Add this test near the vault member tests:

```rust
#[tokio::test]
async fn signed_rotation_endpoint_accepts_client_side_wrappings() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let app = router(test_state_with_storage(storage));
    let owner = register_and_signed_login(
        app.clone(),
        "rotation-owner@example.com",
        b"rotation owner",
        "rotation-owner",
    )
    .await;
    let member = register_user_with_device(
        app.clone(),
        "rotation-member@example.com",
        b"rotation member",
        Some("Rotation Member"),
        "rotation laptop",
        "rotation-device-public-key".to_owned(),
        "rotation-fingerprint".to_owned(),
        "rotation-public-key".to_owned(),
    )
    .await;
    let vault_id = Uuid::parse_str("00000000-0000-0000-0000-000000000177").unwrap();
    let (_status, vault): (StatusCode, VaultResponse) = signed_json_request(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        owner.auth("rotation-create-vault"),
        &CreateVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: Some(vault_id),
            name: "Rotation".to_owned(),
            kind: VaultKind::Shared,
            initial_key_wrapping: json!({"owner": "wrapping-v1"}),
        },
    )
    .await;
    let (_status, _added): (StatusCode, umbra_protocol::VaultMemberResponse) =
        signed_json_request(
            app.clone(),
            Method::POST,
            &format!("/api/v1/vaults/{}/members", vault.vault_id),
            owner.auth("rotation-add-member"),
            &AddVaultMemberRequest {
                protocol_version: PROTOCOL_VERSION,
                user_id: member.user_id,
                role: VaultRole::Editor,
                vault_key_wrapping: json!({"member": "wrapping-v1"}),
            },
        )
        .await;
    let (_status, _removed): (StatusCode, serde_json::Value) = signed_json_request(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/vaults/{}/members/{}", vault.vault_id, member.user_id),
        owner.auth("rotation-remove-member"),
        &json!({}),
    )
    .await;

    let (status, rotated): (StatusCode, RotationStatusResponse) = signed_json_request(
        app,
        Method::POST,
        &format!("/api/v1/vaults/{}/rotate-key", vault.vault_id),
        owner.auth("rotation-finish"),
        &RotateVaultKeyRequest {
            protocol_version: PROTOCOL_VERSION,
            from_generation: 1,
            to_generation: 2,
            new_wrappings: vec![RotationVaultKeyWrapping {
                user_id: owner.user_id,
                device_id: None,
                wrapping_type: "user_public_key".to_owned(),
                envelope: json!({"owner": "wrapping-v2"}),
            }],
            reencrypted_revisions: vec![],
        },
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(rotated.vault_id, vault.vault_id);
    assert_eq!(rotated.current_key_generation, 2);
    assert!(!rotated.needs_key_rotation);
}
```

- [ ] **Step 2: Run server test**

Run:

```bash
cargo test -p umbra-server signed_rotation_endpoint_accepts_client_side_wrappings
```

Expected: PASS if the existing endpoint shape is correct.

- [ ] **Step 3: Commit**

```bash
git add crates/umbra-server/src/tests.rs
git commit -m "test(server): cover vault key rotation endpoint"
```

---

## Task 7: Document Vault Key Rotation

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/protocol.md`

- [ ] **Step 1: Update README**

In `README.md`, after the "Organizations And Shared Vaults" section, add:

````markdown
## Vault Key Rotation

Removing a vault member blocks future sync and marks the vault as needing key rotation. Rotation is a client-side crypto operation:

```bash
umbra crypto rotation-status --vault Platform
umbra crypto rotate-vault-key --vault Platform --dry-run
umbra crypto rotate-vault-key --vault Platform --yes
```

The CLI downloads the latest encrypted item revisions, unlocks the current vault key locally, generates a fresh vault key, reencrypts each latest item revision, wraps the new vault key for every active vault member public key, and uploads only encrypted envelopes to the server.

After removing a member, also rotate any real external credential the removed member may have seen, such as GitHub tokens, API keys, SSH keys, or database passwords. Vault key rotation prevents future Umbra sync access; it cannot erase knowledge already copied.
````

- [ ] **Step 2: Update architecture docs**

In `docs/architecture.md`, after the direct membership paragraph under `## Sharing Flow`, add:

```markdown
Vault key rotation is also client-side. An owner/admin requests rotation status, syncs the latest vault revisions, decrypts the latest item revisions with the old vault key, generates a new random vault key, reencrypts each item with the new key, wraps the new key for active members, and submits `RotateVaultKeyRequest`. The server validates role and revision preconditions, revokes old wrappings, stores new encrypted wrappings and item revisions, increments key generation, and clears `needs_key_rotation`.
```

- [ ] **Step 3: Update protocol docs**

In `docs/protocol.md`, after the "Vault Members" section, add:

````markdown
### Vault Key Rotation

```http
GET /api/v1/vaults/:vault_id/rotation-status
POST /api/v1/vaults/:vault_id/rotate-key
```

`rotation-status` returns the current key generation and whether the vault needs rotation. `rotate-key` accepts `RotateVaultKeyRequest` with `from_generation`, `to_generation`, new encrypted vault-key wrappings, and reencrypted item revisions. The server never receives the new vault key or plaintext item contents.
````

- [ ] **Step 4: Run docs-adjacent checks**

Run:

```bash
cargo test -p umbra-cli parses_crypto_rotation_commands
cargo test -p umbra-cli build_rotation_request_rewraps_members_and_reencrypts_items
cargo test -p umbra-server signed_rotation_endpoint_accepts_client_side_wrappings
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/architecture.md docs/protocol.md
git commit -m "docs(cli): document vault key rotation"
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

Expected commits:

```txt
feat(protocol): include vault member public keys
feat(server): include public keys in vault members
feat(cli): add crypto rotation commands
feat(cli): build vault rotation requests
feat(cli): rotate vault keys
test(server): cover vault key rotation endpoint
docs(cli): document vault key rotation
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

- The plan implements the missing operational piece after vault member removal: actual key rotation.
- The server still never sees plaintext vault keys or item plaintext.
- The CLI performs all unwrap/reencrypt/rewrap operations locally.
- Active members get new user-public-key wrappings.
- Removed members stop receiving sync and do not get new wrappings.
- Empty vaults can rotate because the request can contain no item revisions.
- Stale cache/item generation is rejected before upload.

Placeholder scan:

- No task uses placeholder phrases or unspecified edge handling.
- Each code-changing step includes exact code blocks and exact commands.

Type consistency:

- `VaultMemberResponse.public_key` is defined in Task 1 and used by server/CLI tasks.
- `RotationStatusResponse`, `RotateVaultKeyRequest`, `RotationVaultKeyWrapping`, and `RotationItemRevision` already exist in protocol and are imported by the CLI in Task 4.
- `DecryptedCachedItem.kind` is added before `build_rotation_request` uses it.
- CLI commands are named consistently: `crypto rotation-status` and `crypto rotate-vault-key`.
