# CLI Real Crypto Items Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the CLI create, cache, and read real zero-knowledge items without requiring users to hand-write `--envelope-json`.

**Architecture:** Keep cryptography client-side in `umbra-cli` by reusing `umbra-crypto` for user keypairs, vault keys, vault key wrappings, and item envelopes. The server remains a ciphertext sync service; it still stores `initial_key_wrapping` and item `envelope` JSON without decrypting. This MVP supports the active user as vault owner and prepares the same stored wrapping format that shared vaults will use later.

**Tech Stack:** Rust, clap, dialoguer/rpassword, serde_json, umbra-core, umbra-crypto, umbra-protocol, rusqlite cache.

---

## Scope

This plan implements the next usable vertical slice:

- registration creates real client crypto material;
- vault creation generates a real vault key and real owner wrapping;
- item creation accepts plaintext fields and encrypts locally;
- sync stores envelopes/wrappings in SQLite cache;
- item get decrypts a cached item locally;
- `secret set/get` works for `project/env KEY VALUE` against cached encrypted items.

This plan intentionally does not implement shared vault invite acceptance, organization member management, vault key rotation, SQLCipher/local encrypted cache, browser/web UI, or local-only vaults.

## File Structure

- Modify `crates/umbra-cli/Cargo.toml`: add dependency on `umbra-crypto`.
- Modify `crates/umbra-cli/src/error.rs`: add crypto and unlock/config error variants.
- Modify `crates/umbra-cli/src/config.rs`: store public key, encrypted private key envelope, KDF params, and user secret key reference for the active profile.
- Create `crates/umbra-cli/src/crypto_state.rs`: own all CLI crypto state loading/saving/unlocking helpers.
- Create `crates/umbra-cli/src/item_plaintext.rs`: build login/env/custom plaintext item objects from CLI input.
- Modify `crates/umbra-cli/src/cache.rs`: expose cached key wrapping lookup and latest item lookup for production decrypt flows.
- Modify `crates/umbra-cli/src/main.rs`: add `unlock`, friendlier item commands, and `secret` commands.
- Modify `crates/umbra-cli/src/commands.rs`: wire register/vault/item/secret flows to crypto helpers.
- Modify `crates/umbra-cli/src/tests.rs`: parser/config unit coverage.
- Modify `README.md`: document the new CLI happy path.
- Modify `docs/crypto.md`: document current CLI crypto storage and limitations.

---

### Task 1: Add CLI Crypto Dependency and Error Plumbing

**Files:**
- Modify: `crates/umbra-cli/Cargo.toml`
- Modify: `crates/umbra-cli/src/error.rs`
- Test: `cargo check -p umbra-cli`

- [ ] **Step 1: Add `umbra-crypto` to CLI dependencies**

Edit `crates/umbra-cli/Cargo.toml` and add this dependency in `[dependencies]`:

```toml
umbra-crypto = { path = "../umbra-crypto" }
```

- [ ] **Step 2: Add CLI error variants**

Edit `crates/umbra-cli/src/error.rs` so `CliError` contains these variants:

```rust
#[error("crypto error: {0}")]
Crypto(#[from] umbra_crypto::CryptoError),

#[error("profile is missing client crypto material; run `umbra register` again for a fresh profile")]
MissingCryptoMaterial,

#[error("no vault key wrapping found in local cache for vault {0}")]
MissingVaultKeyWrapping(uuid::Uuid),

#[error("item is not in local cache; run `umbra sync run --vault {0}` first")]
MissingCachedItem(uuid::Uuid),
```

Keep all existing variants.

- [ ] **Step 3: Verify the dependency compiles**

Run:

```bash
cargo check -p umbra-cli
```

Expected: `Finished` with no errors.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-cli/Cargo.toml crates/umbra-cli/src/error.rs
git commit -m "feat(cli): prepare crypto errors"
```

---

### Task 2: Persist Client Crypto Material in CLI Config

**Files:**
- Modify: `crates/umbra-cli/src/config.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Test: `cargo test -p umbra-cli config_roundtrips_toml`

- [ ] **Step 1: Write failing config roundtrip assertions**

In `crates/umbra-cli/src/tests.rs`, extend `config_roundtrips_toml` by setting the new fields on `ProfileConfig`:

```rust
client_public_key: Some("client-public-key".to_owned()),
encrypted_user_private_key: Some(serde_json::json!({
    "version": 1,
    "suite": "UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1",
    "nonce": "nonce",
    "aad": "aad",
    "ciphertext": "ciphertext"
})),
kdf_params: Some(umbra_crypto::Argon2idParams::new(
    "balanced",
    64,
    3,
    1,
    umbra_crypto::Salt::from_bytes([1u8; 16]).to_base64url(),
)),
user_secret_key: Some("secret-key".to_owned()),
```

After decoding, assert:

```rust
let profile = decoded.profiles.get("personal").unwrap();
assert_eq!(profile.client_public_key.as_deref(), Some("client-public-key"));
assert!(profile.encrypted_user_private_key.is_some());
assert_eq!(profile.kdf_params.as_ref().unwrap().profile, "balanced");
assert_eq!(profile.user_secret_key.as_deref(), Some("secret-key"));
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p umbra-cli config_roundtrips_toml
```

Expected: FAIL because `ProfileConfig` does not have those fields.

- [ ] **Step 3: Add fields to `ProfileConfig`**

In `crates/umbra-cli/src/config.rs`, add these fields to `ProfileConfig`:

```rust
#[serde(default)]
pub client_public_key: Option<String>,
#[serde(default)]
pub encrypted_user_private_key: Option<serde_json::Value>,
#[serde(default)]
pub kdf_params: Option<umbra_crypto::Argon2idParams>,
#[serde(default)]
pub user_secret_key: Option<String>,
```

Update `Default for ProfileConfig`:

```rust
client_public_key: None,
encrypted_user_private_key: None,
kdf_params: None,
user_secret_key: None,
```

- [ ] **Step 4: Run test and verify it passes**

Run:

```bash
cargo test -p umbra-cli config_roundtrips_toml
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/config.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): persist client crypto material"
```

---

### Task 3: Add `crypto_state` Helpers for Register and Unlock

**Files:**
- Create: `crates/umbra-cli/src/crypto_state.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Test: `cargo test -p umbra-cli crypto_state`

- [ ] **Step 1: Create failing tests for crypto state**

Create module tests in `crates/umbra-cli/src/crypto_state.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use umbra_crypto::MasterPassword;

    #[test]
    fn generated_account_crypto_unlocks_private_key() {
        let material = NewAccountCrypto::generate(&MasterPassword::new(b"correct".to_vec()))
            .expect("generate account crypto");

        let unlocked = material
            .unlock(&MasterPassword::new(b"correct".to_vec()))
            .expect("unlock private key");

        assert_eq!(unlocked.public_key, material.public_key);
        assert!(material.user_secret_key.to_base64url().len() > 20);
    }

    #[test]
    fn generated_account_crypto_rejects_wrong_password() {
        let material = NewAccountCrypto::generate(&MasterPassword::new(b"correct".to_vec()))
            .expect("generate account crypto");

        let result = material.unlock(&MasterPassword::new(b"wrong".to_vec()));

        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p umbra-cli crypto_state
```

Expected: FAIL because `crypto_state` module does not exist.

- [ ] **Step 3: Implement `crypto_state.rs`**

Create `crates/umbra-cli/src/crypto_state.rs`:

```rust
use umbra_crypto::{
    AadV1, Argon2idParams, CryptoEnvelopeV1, MasterPassword, Salt, UserKeypair, UserPrivateKey,
    UserPublicKey, UserSecretKey, derive_account_kek, decrypt_user_private_key,
    encrypt_user_private_key, generate_user_keypair,
};

use crate::config::ProfileConfig;
use crate::error::CliError;

#[derive(Debug, Clone)]
pub struct NewAccountCrypto {
    pub public_key: UserPublicKey,
    pub user_secret_key: UserSecretKey,
    pub kdf_params: Argon2idParams,
    pub encrypted_private_key: CryptoEnvelopeV1,
}

#[derive(Debug, Clone)]
pub struct UnlockedAccountCrypto {
    pub public_key: UserPublicKey,
    pub private_key: UserPrivateKey,
}

impl NewAccountCrypto {
    pub fn generate(password: &MasterPassword) -> Result<Self, CliError> {
        let user_secret_key = UserSecretKey::generate();
        let keypair = generate_user_keypair();
        let kdf_params = Argon2idParams::new(
            "balanced",
            64,
            3,
            1,
            Salt::generate().to_base64url(),
        );
        let kek = derive_account_kek(password, &user_secret_key, &kdf_params)?;
        let aad = AadV1::user_private_key(keypair.public_key.to_base64url());
        let encrypted_private_key = encrypt_user_private_key(&kek, &keypair.private_key, aad)?;

        Ok(Self {
            public_key: keypair.public_key,
            user_secret_key,
            kdf_params,
            encrypted_private_key,
        })
    }

    pub fn unlock(&self, password: &MasterPassword) -> Result<UnlockedAccountCrypto, CliError> {
        let kek = derive_account_kek(password, &self.user_secret_key, &self.kdf_params)?;
        let aad = AadV1::user_private_key(self.public_key.to_base64url());
        let private_key = decrypt_user_private_key(&kek, &aad, &self.encrypted_private_key)?;
        Ok(UnlockedAccountCrypto {
            public_key: self.public_key,
            private_key,
        })
    }
}

pub fn load_unlocked_profile(
    profile: &ProfileConfig,
    password: &MasterPassword,
) -> Result<UnlockedAccountCrypto, CliError> {
    let public_key = profile
        .client_public_key
        .as_deref()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(UserPublicKey::from_base64url)?;
    let user_secret_key = profile
        .user_secret_key
        .as_deref()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(UserSecretKey::from_base64url)?;
    let kdf_params = profile
        .kdf_params
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)?;
    let encrypted_private_key: CryptoEnvelopeV1 = serde_json::from_value(
        profile
            .encrypted_user_private_key
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?,
    )?;

    let material = NewAccountCrypto {
        public_key,
        user_secret_key,
        kdf_params,
        encrypted_private_key,
    };
    material.unlock(password)
}

pub fn keypair_from_unlocked(unlocked: &UnlockedAccountCrypto) -> UserKeypair {
    UserKeypair {
        public_key: unlocked.public_key,
        private_key: unlocked.private_key.clone(),
    }
}
```

- [ ] **Step 4: Register module in `main.rs`**

Add:

```rust
mod crypto_state;
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p umbra-cli crypto_state
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/crypto_state.rs crates/umbra-cli/src/main.rs
git commit -m "feat(cli): add account crypto state"
```

---

### Task 4: Register Creates Real Client Crypto Material

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/opaque.rs`
- Test: `cargo test -p umbra-cli`

- [ ] **Step 1: Change OPAQUE register to accept account crypto**

In `crates/umbra-cli/src/opaque.rs`, change `opaque_register` signature to:

```rust
pub async fn opaque_register(
    client: &UmbraHttpClient,
    email: &str,
    password: &[u8],
    device_name: &str,
    device_public_key: String,
    device_fingerprint: String,
    account_public_key: String,
    encrypted_user_private_key: serde_json::Value,
) -> Result<RegisterResponse, CliError>
```

Inside the `OpaqueRegisterFinishRequest`, replace the existing placeholders:

```rust
account_public_key,
encrypted_user_private_key,
initial_device: DeviceRegisterRequest {
    protocol_version: PROTOCOL_VERSION,
    name: device_name.to_owned(),
    public_key: device_public_key,
    fingerprint: device_fingerprint,
},
```

- [ ] **Step 2: Generate crypto material during register**

In `crates/umbra-cli/src/commands.rs`, in `Command::Register`, after reading the password, add:

```rust
let account_crypto =
    crate::crypto_state::NewAccountCrypto::generate(&umbra_crypto::MasterPassword::new(
        password.clone(),
    ))?;
```

Pass these values into `opaque_register`:

```rust
account_crypto.public_key.to_base64url(),
serde_json::to_value(&account_crypto.encrypted_private_key)?,
```

After successful registration, save these fields into `profile_config`:

```rust
profile_config.client_public_key = Some(account_crypto.public_key.to_base64url());
profile_config.encrypted_user_private_key =
    Some(serde_json::to_value(&account_crypto.encrypted_private_key)?);
profile_config.kdf_params = Some(account_crypto.kdf_params);
profile_config.user_secret_key = Some(account_crypto.user_secret_key.to_base64url());
```

- [ ] **Step 3: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-cli/src/commands.rs crates/umbra-cli/src/opaque.rs
git commit -m "feat(cli): create crypto material on register"
```

---

### Task 5: Vault Create Generates Vault Key and Owner Wrapping

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Test: `cargo test -p umbra-cli parses_vault_create_without_wrapping_json`

- [ ] **Step 1: Write parser test for friendlier vault create**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_vault_create_without_wrapping_json() {
    let cli = parse(["umbra", "vault", "create", "Personal"]);

    let Command::Vault(VaultCommand::Create {
        name,
        wrapping_json,
    }) = cli.command
    else {
        panic!("expected vault create");
    };

    assert_eq!(name.as_deref(), Some("Personal"));
    assert!(wrapping_json.is_none());
}
```

- [ ] **Step 2: Run parser test**

Run:

```bash
cargo test -p umbra-cli parses_vault_create_without_wrapping_json
```

Expected: PASS if current parser already accepts optional wrapping JSON.

- [ ] **Step 3: Generate wrapping when user does not pass JSON**

In `crates/umbra-cli/src/commands.rs`, replace the `wrapping_json` prompt branch in `VaultCommand::Create` with:

```rust
let initial_key_wrapping = match wrapping_json {
    Some(wrapping_json) => serde_json::from_str(&wrapping_json)?,
    None => {
        let password = rpassword::prompt_password("Master password: ")?;
        let unlocked = crate::crypto_state::load_unlocked_profile(
            profile,
            &umbra_crypto::MasterPassword::new(password.into_bytes()),
        )?;
        let vault_key = umbra_crypto::generate_vault_key();
        let aad = umbra_crypto::AadV1::vault_key_wrapping("pending-vault");
        let wrapping = umbra_crypto::wrap_vault_key_for_user(
            &unlocked.public_key,
            &vault_key,
            aad,
        )?;
        serde_json::to_value(wrapping)?
    }
};
```

Use `initial_key_wrapping` in `CreateVaultRequest`.

Note: this uses `"pending-vault"` because the server currently generates `vault_id` after receiving the request. Task 6 adds a protocol-compatible client vault id so AAD can bind to the real vault id before upload.

- [ ] **Step 4: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 5: Commit temporary owner wrapping**

```bash
git add crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): generate vault wrapping on create"
```

---

### Task 6: Let Client Supply Vault ID for Correct Wrapping AAD

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `cargo test -p umbra-server creates_vault`

- [ ] **Step 1: Extend `CreateVaultRequest`**

In `crates/umbra-protocol/src/lib.rs`, change `CreateVaultRequest` to:

```rust
pub struct CreateVaultRequest {
    pub protocol_version: u16,
    pub vault_id: Option<VaultId>,
    pub name: String,
    pub kind: VaultKind,
    pub initial_key_wrapping: serde_json::Value,
}
```

Also change `CreateOrgVaultRequest` the same way:

```rust
pub struct CreateOrgVaultRequest {
    pub protocol_version: u16,
    pub vault_id: Option<VaultId>,
    pub name: String,
    pub kind: VaultKind,
    pub initial_key_wrapping: serde_json::Value,
}
```

- [ ] **Step 2: Update server vault creation**

In `crates/umbra-server/src/http.rs`, where a vault id is generated, use:

```rust
let vault_id = requested_vault_id.unwrap_or_else(Uuid::new_v4);
```

Pass `request.vault_id` from both personal/shared and org vault handlers into the internal helper.

- [ ] **Step 3: Update server tests**

In `crates/umbra-server/src/tests.rs`, add `vault_id: None,` to every `CreateVaultRequest` and `CreateOrgVaultRequest` literal.

Add one assertion test:

```rust
#[tokio::test]
async fn create_vault_accepts_client_supplied_id() {
    let app = TestApp::spawn().await;
    let session = app.register_and_login("vault-id@example.com").await;
    let requested_id = Uuid::parse_str("00000000-0000-0000-0000-00000000abcd").unwrap();

    let (_status, response): (StatusCode, VaultResponse) = app
        .json_request(
            Method::POST,
            "/api/v1/vaults",
            Some(&session),
            &CreateVaultRequest {
                protocol_version: PROTOCOL_VERSION,
                vault_id: Some(requested_id),
                name: "Personal".to_owned(),
                kind: VaultKind::Personal,
                initial_key_wrapping: json!({"wrapped": true}),
            },
        )
        .await;

    assert_eq!(response.vault_id, requested_id);
}
```

If the test helper names differ, use the existing helper pattern in the same file and keep the request body exactly as shown.

- [ ] **Step 4: Update CLI vault create AAD**

In `crates/umbra-cli/src/commands.rs`, generate `vault_id` before wrapping:

```rust
let requested_vault_id = uuid::Uuid::new_v4();
let aad = umbra_crypto::AadV1::vault_key_wrapping(requested_vault_id.to_string());
```

Send it in the request:

```rust
vault_id: Some(requested_vault_id),
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
cargo test -p umbra-protocol
cargo test -p umbra-server create_vault
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs crates/umbra-cli/src/commands.rs
git commit -m "feat(protocol): allow client vault ids"
```

---

### Task 7: Build Plaintext Item Helpers

**Files:**
- Create: `crates/umbra-cli/src/item_plaintext.rs`
- Modify: `crates/umbra-cli/src/main.rs`
- Test: `cargo test -p umbra-cli item_plaintext`

- [ ] **Step 1: Create tests for plaintext builders**

Create `crates/umbra-cli/src/item_plaintext.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use umbra_core::{ItemFieldKind, ItemKind};

    #[test]
    fn builds_env_bundle_with_secret_field() {
        let item = build_secret_bundle("pulzar/dev", "DATABASE_URL", "postgres://db");

        assert_eq!(item.title, "pulzar/dev");
        assert_eq!(item.tags, vec!["env", "pulzar", "dev"]);
        assert_eq!(item.fields[0].name, "DATABASE_URL");
        assert_eq!(item.fields[0].kind, ItemFieldKind::Secret);
        assert!(item.fields[0].sensitive);
    }

    #[test]
    fn default_fields_for_login() {
        let fields = default_fields_for_kind(&ItemKind::Login);

        assert_eq!(fields, vec!["username", "password", "url"]);
    }
}
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p umbra-cli item_plaintext
```

Expected: FAIL because functions do not exist.

- [ ] **Step 3: Implement item plaintext helpers**

Add this implementation above the tests:

```rust
use umbra_core::{ItemField, ItemFieldKind, ItemKind, ItemPlaintextV1};

pub fn default_fields_for_kind(kind: &ItemKind) -> Vec<&'static str> {
    match kind {
        ItemKind::Login => vec!["username", "password", "url"],
        ItemKind::SecureNote => Vec::new(),
        ItemKind::SshKey => vec!["private_key", "public_key", "passphrase"],
        ItemKind::ApiKey => vec!["key"],
        ItemKind::Token => vec!["token"],
        ItemKind::EnvVar => vec!["value"],
        ItemKind::EnvBundle => Vec::new(),
        ItemKind::CreditCard => vec!["number", "holder", "expires", "cvv"],
        ItemKind::Custom(_) => Vec::new(),
    }
}

pub fn field_kind_for_name(name: &str) -> ItemFieldKind {
    match name {
        "username" => ItemFieldKind::Username,
        "password" | "passphrase" | "cvv" => ItemFieldKind::Password,
        "url" => ItemFieldKind::Url,
        "token" | "key" | "private_key" => ItemFieldKind::Secret,
        "DATABASE_URL" | "REDIS_URL" | "OPENAI_API_KEY" => ItemFieldKind::Secret,
        _ => ItemFieldKind::Text,
    }
}

pub fn is_sensitive_field(name: &str, kind: &ItemFieldKind) -> bool {
    matches!(
        kind,
        ItemFieldKind::Password
            | ItemFieldKind::Token
            | ItemFieldKind::Secret
            | ItemFieldKind::Totp
            | ItemFieldKind::CreditCardNumber
    ) || name.contains("KEY")
        || name.contains("SECRET")
        || name.contains("TOKEN")
        || name == "DATABASE_URL"
}

pub fn build_item(
    title: &str,
    fields: Vec<(String, String)>,
    notes: Option<String>,
    tags: Vec<String>,
) -> ItemPlaintextV1 {
    let mut item = ItemPlaintextV1::new(title);
    item.notes = notes;
    item.tags = tags;
    item.fields = fields
        .into_iter()
        .map(|(name, value)| {
            let kind = field_kind_for_name(&name);
            let sensitive = is_sensitive_field(&name, &kind);
            ItemField::new(name, kind, value, sensitive)
        })
        .collect();
    item
}

pub fn build_secret_bundle(project_env: &str, key: &str, value: &str) -> ItemPlaintextV1 {
    let mut tags = vec!["env".to_owned()];
    if let Some((project, env)) = project_env.split_once('/') {
        tags.push(project.to_owned());
        tags.push(env.to_owned());
    }

    build_item(
        project_env,
        vec![(key.to_owned(), value.to_owned())],
        None,
        tags,
    )
}
```

- [ ] **Step 4: Register module**

Add to `crates/umbra-cli/src/main.rs`:

```rust
mod item_plaintext;
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p umbra-cli item_plaintext
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/item_plaintext.rs crates/umbra-cli/src/main.rs
git commit -m "feat(cli): add item plaintext builders"
```

---

### Task 8: Expose Cache Lookup Needed for Decrypt

**Files:**
- Modify: `crates/umbra-cli/src/cache.rs`
- Test: `cargo test -p umbra-cli cache`

- [ ] **Step 1: Make `CachedKeyWrapping` available outside tests**

In `crates/umbra-cli/src/cache.rs`, remove `#[cfg(test)]` from `CachedKeyWrapping` and from `list_key_wrappings`.

- [ ] **Step 2: Add latest owner wrapping helper**

Add this method to `impl LocalCache`:

```rust
pub fn latest_key_wrapping(
    &self,
    vault_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> Result<Option<CachedKeyWrapping>, CliError> {
    let mut statement = self.connection.prepare(
        "
        SELECT id, vault_id, user_id, device_id, wrapping_type, envelope_json, key_generation
        FROM vault_key_wrappings
        WHERE vault_id = ?1 AND user_id = ?2
        ORDER BY key_generation DESC
        LIMIT 1
        ",
    )?;
    let mut rows = statement.query_map(
        params![vault_id.to_string(), user_id.to_string()],
        cached_key_wrapping_from_row,
    )?;
    rows.next().transpose()
}
```

- [ ] **Step 3: Add test for latest wrapping**

Extend `upserts_sync_changes_and_tracks_cursor`:

```rust
let wrapping = cache
    .latest_key_wrapping(vault_id, user_id)
    .unwrap()
    .expect("cached wrapping");
assert_eq!(wrapping.vault_id, vault_id);
assert_eq!(wrapping.user_id, user_id);
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p umbra-cli cache
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/cache.rs
git commit -m "feat(cli): expose cached key wrapping lookup"
```

---

### Task 9: Encrypt Item Create Locally

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Test: `cargo test -p umbra-cli parses_item_create_plaintext`

- [ ] **Step 1: Add friendly item command shape**

In `crates/umbra-cli/src/main.rs`, replace `ItemCommand::Create` with:

```rust
Create {
    #[arg(long)]
    vault_id: VaultId,
    #[arg(long, value_parser = parse_item_kind)]
    kind: ItemKind,
    #[arg(long)]
    title: Option<String>,
    #[arg(long = "field")]
    fields: Vec<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long)]
    envelope_json: Option<String>,
},
```

Keep `--envelope-json` as an escape hatch.

- [ ] **Step 2: Add parser test**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_item_create_plaintext() {
    let vault_id = "00000000-0000-0000-0000-000000000001";
    let cli = parse([
        "umbra",
        "item",
        "create",
        "--vault-id",
        vault_id,
        "--kind",
        "login",
        "--title",
        "GitHub",
        "--field",
        "username=miguel",
        "--field",
        "password=secret",
    ]);

    let Command::Item(crate::ItemCommand::Create {
        title, fields, envelope_json, ..
    }) = cli.command
    else {
        panic!("expected item create");
    };

    assert_eq!(title.as_deref(), Some("GitHub"));
    assert_eq!(fields, vec!["username=miguel", "password=secret"]);
    assert!(envelope_json.is_none());
}
```

- [ ] **Step 3: Run parser test**

Run:

```bash
cargo test -p umbra-cli parses_item_create_plaintext
```

Expected: PASS after command shape compiles.

- [ ] **Step 4: Implement local encryption branch**

In `crates/umbra-cli/src/commands.rs`, update the create arm:

```rust
Command::Item(ItemCommand::Create {
    vault_id,
    kind,
    title,
    fields,
    notes,
    tags,
    envelope_json,
}) => {
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let envelope = match envelope_json {
        Some(envelope_json) => serde_json::from_str(&envelope_json)?,
        None => {
            let password = rpassword::prompt_password("Master password: ")?;
            let unlocked = crate::crypto_state::load_unlocked_profile(
                profile,
                &umbra_crypto::MasterPassword::new(password.into_bytes()),
            )?;
            let user_id = profile.user_id.ok_or(CliError::MissingCryptoMaterial)?;
            let cache = crate::cache::LocalCache::open(&config.active_profile)?;
            let wrapping = cache
                .latest_key_wrapping(vault_id, user_id)?
                .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
            let wrapping_envelope: umbra_crypto::VaultKeyWrappingEnvelopeV1 =
                serde_json::from_value(wrapping.envelope)?;
            let wrapping_aad = umbra_crypto::AadV1::vault_key_wrapping(vault_id.to_string());
            let vault_key =
                umbra_crypto::unwrap_vault_key(&unlocked.private_key, &wrapping_aad, &wrapping_envelope)?;

            let parsed_fields = parse_field_pairs(fields)?;
            let item_title = title.unwrap_or_else(|| "Untitled".to_owned());
            let plaintext = crate::item_plaintext::build_item(&item_title, parsed_fields, notes, tags);
            let plaintext_json = serde_json::to_vec(&plaintext)?;
            let item_id = uuid::Uuid::new_v4();
            let item_aad = umbra_crypto::AadV1::item(
                vault_id.to_string(),
                item_id.to_string(),
                1,
                format!("{kind:?}"),
            );
            serde_json::to_value(umbra_crypto::encrypt_item(
                &vault_key,
                item_aad,
                &plaintext_json,
            )?)?
        }
    };
    let response: Value = client
        .post(
            &format!("/api/v1/vaults/{vault_id}/items"),
            &CreateItemRequest {
                protocol_version: PROTOCOL_VERSION,
                vault_id,
                kind,
                envelope,
            },
        )
        .await?;
    print_json(&response)
}
```

Add helper near `parse_item_kind`:

```rust
fn parse_field_pairs(fields: Vec<String>) -> Result<Vec<(String, String)>, CliError> {
    fields
        .into_iter()
        .map(|field| {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| CliError::Input("field must use name=value format"))?;
            Ok((name.to_owned(), value.to_owned()))
        })
        .collect()
}
```

Note: Task 10 fixes the generated `item_id` mismatch by adding client-supplied item ids to the protocol. Do not ship this task alone.

- [ ] **Step 5: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 6: Commit temporary local encryption**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): encrypt item payloads locally"
```

---

### Task 10: Let Client Supply Item ID for Correct Item AAD

**Files:**
- Modify: `crates/umbra-protocol/src/lib.rs`
- Modify: `crates/umbra-server/src/http.rs`
- Modify: `crates/umbra-server/src/tests.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `cargo test -p umbra-server create_item`

- [ ] **Step 1: Extend `CreateItemRequest`**

In `crates/umbra-protocol/src/lib.rs`, change the struct to:

```rust
pub struct CreateItemRequest {
    pub protocol_version: u16,
    pub item_id: Option<ItemId>,
    pub vault_id: VaultId,
    pub kind: ItemKind,
    pub envelope: serde_json::Value,
}
```

- [ ] **Step 2: Update server item creation**

In `crates/umbra-server/src/http.rs`, where item id is generated for `create_item`, use:

```rust
let item_id = request.item_id.unwrap_or_else(Uuid::new_v4);
```

Persist that `item_id` instead of generating another id deeper in the handler. If storage currently generates it, pass `item_id` into the storage method and update the method signature.

- [ ] **Step 3: Update tests**

In `crates/umbra-server/src/tests.rs`, add `item_id: None,` to all `CreateItemRequest` literals.

Add one test:

```rust
#[tokio::test]
async fn create_item_accepts_client_supplied_id() {
    let app = TestApp::spawn().await;
    let session = app.register_and_login("item-id@example.com").await;
    let vault = app.create_vault(&session, "Personal").await;
    let requested_id = Uuid::parse_str("00000000-0000-0000-0000-00000000dcba").unwrap();

    let (_status, response): (StatusCode, ItemRevisionResponse) = app
        .json_request(
            Method::POST,
            &format!("/api/v1/vaults/{}/items", vault.vault_id),
            Some(&session),
            &CreateItemRequest {
                protocol_version: PROTOCOL_VERSION,
                item_id: Some(requested_id),
                vault_id: vault.vault_id,
                kind: ItemKind::ApiKey,
                envelope: json!({"ciphertext": "abc"}),
            },
        )
        .await;

    assert_eq!(response.item_id, requested_id);
}
```

If helper names differ, use existing server test style and keep the request body exact.

- [ ] **Step 4: Use client item id in CLI request and AAD**

In `crates/umbra-cli/src/commands.rs`, keep:

```rust
let item_id = uuid::Uuid::new_v4();
```

Use it in `CreateItemRequest`:

```rust
item_id: Some(item_id),
```

Also add `item_id: None,` in the `--envelope-json` branch if no generated id is needed.

- [ ] **Step 5: Run focused tests**

Run:

```bash
cargo test -p umbra-protocol
cargo test -p umbra-server create_item
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-protocol/src/lib.rs crates/umbra-server/src/http.rs crates/umbra-server/src/tests.rs crates/umbra-storage/src crates/umbra-cli/src/commands.rs
git commit -m "feat(protocol): allow client item ids"
```

---

### Task 11: Decrypt Cached Item Get

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `cargo test -p umbra-cli`

- [ ] **Step 1: Update cached item get behavior**

In `crates/umbra-cli/src/commands.rs`, change the cached `ItemCommand::Get` branch so it:

```rust
let cache = crate::cache::LocalCache::open(&config.active_profile)?;
let revision = cache
    .latest_item_revision(vault_id, item_id)?
    .ok_or(CliError::MissingCachedItem(vault_id))?;
let profile = active_profile(&config)?;
let user_id = profile.user_id.ok_or(CliError::MissingCryptoMaterial)?;
let wrapping = cache
    .latest_key_wrapping(vault_id, user_id)?
    .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
let password = rpassword::prompt_password("Master password: ")?;
let unlocked = crate::crypto_state::load_unlocked_profile(
    profile,
    &umbra_crypto::MasterPassword::new(password.into_bytes()),
)?;
let wrapping_envelope: umbra_crypto::VaultKeyWrappingEnvelopeV1 =
    serde_json::from_value(wrapping.envelope)?;
let wrapping_aad = umbra_crypto::AadV1::vault_key_wrapping(vault_id.to_string());
let vault_key =
    umbra_crypto::unwrap_vault_key(&unlocked.private_key, &wrapping_aad, &wrapping_envelope)?;
let envelope: umbra_crypto::CryptoEnvelopeV1 = serde_json::from_value(revision.envelope)?;
let item_aad = umbra_crypto::AadV1::item(
    vault_id.to_string(),
    item_id.to_string(),
    revision.revision,
    "unknown".to_owned(),
);
let plaintext = umbra_crypto::decrypt_item(&vault_key, &item_aad, &envelope)?;
let item: umbra_core::ItemPlaintextV1 = serde_json::from_slice(&plaintext)?;
print_json(&item)
```

- [ ] **Step 2: Fix kind/AAD mismatch with envelope metadata**

The previous step uses `"unknown"` and will fail for real encrypted items. Before committing, change Task 9 item AAD kind from `format!("{kind:?}")` to a stable string:

```rust
let kind_name = item_kind_name(&kind);
```

Add helper:

```rust
fn item_kind_name(kind: &ItemKind) -> String {
    match kind {
        ItemKind::Login => "login".to_owned(),
        ItemKind::SecureNote => "secure_note".to_owned(),
        ItemKind::SshKey => "ssh_key".to_owned(),
        ItemKind::ApiKey => "api_key".to_owned(),
        ItemKind::Token => "token".to_owned(),
        ItemKind::EnvVar => "env_var".to_owned(),
        ItemKind::EnvBundle => "env_bundle".to_owned(),
        ItemKind::CreditCard => "credit_card".to_owned(),
        ItemKind::Custom(name) => format!("custom:{name}"),
    }
}
```

Add an unencrypted metadata wrapper around encrypted item envelopes in Task 9:

```rust
serde_json::json!({
    "kind": kind_name,
    "crypto": umbra_crypto::encrypt_item(&vault_key, item_aad, &plaintext_json)?
})
```

In item get, parse:

```rust
let kind_name = revision
    .envelope
    .get("kind")
    .and_then(|value| value.as_str())
    .ok_or_else(|| CliError::Input("cached item envelope missing kind"))?
    .to_owned();
let envelope_value = revision
    .envelope
    .get("crypto")
    .cloned()
    .ok_or_else(|| CliError::Input("cached item envelope missing crypto"))?;
let envelope: umbra_crypto::CryptoEnvelopeV1 = serde_json::from_value(envelope_value)?;
let item_aad = umbra_crypto::AadV1::item(
    vault_id.to_string(),
    item_id.to_string(),
    revision.revision,
    kind_name,
);
```

- [ ] **Step 3: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): decrypt cached items"
```

---

### Task 12: Add `secret set/get` CLI

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`
- Test: `cargo test -p umbra-cli parses_secret_commands`

- [ ] **Step 1: Add command enum**

In `crates/umbra-cli/src/main.rs`, add to `Command`:

```rust
Secret(SecretCommand),
```

Add enum:

```rust
#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    Set {
        project_env: String,
        key: String,
        value: Option<String>,
        #[arg(long)]
        vault_id: VaultId,
    },
    Get {
        project_env: String,
        key: String,
        #[arg(long)]
        vault_id: VaultId,
    },
}
```

Import it in `commands.rs`:

```rust
use crate::{..., SecretCommand, ...};
```

- [ ] **Step 2: Add parser test**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_secret_commands() {
    let vault_id = "00000000-0000-0000-0000-000000000001";
    let set = parse([
        "umbra",
        "secret",
        "set",
        "pulzar/dev",
        "DATABASE_URL",
        "postgres://db",
        "--vault-id",
        vault_id,
    ]);
    assert!(matches!(
        set.command,
        Command::Secret(crate::SecretCommand::Set { .. })
    ));

    let get = parse([
        "umbra",
        "secret",
        "get",
        "pulzar/dev",
        "DATABASE_URL",
        "--vault-id",
        vault_id,
    ]);
    assert!(matches!(
        get.command,
        Command::Secret(crate::SecretCommand::Get { .. })
    ));
}
```

- [ ] **Step 3: Run parser test**

Run:

```bash
cargo test -p umbra-cli parses_secret_commands
```

Expected: PASS after command enum compiles.

- [ ] **Step 4: Implement `secret set` as env bundle item creation**

In `commands.rs`, add a command arm:

```rust
Command::Secret(SecretCommand::Set {
    project_env,
    key,
    value,
    vault_id,
}) => {
    let value = match value {
        Some(value) => value,
        None => rpassword::prompt_password("Value: ")?,
    };
    let profile = active_profile(&config)?;
    require_login(profile)?;
    let client = UmbraHttpClient::new(profile)?;
    let password = rpassword::prompt_password("Master password: ")?;
    let unlocked = crate::crypto_state::load_unlocked_profile(
        profile,
        &umbra_crypto::MasterPassword::new(password.into_bytes()),
    )?;
    let user_id = profile.user_id.ok_or(CliError::MissingCryptoMaterial)?;
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let wrapping = cache
        .latest_key_wrapping(vault_id, user_id)?
        .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
    let wrapping_envelope: umbra_crypto::VaultKeyWrappingEnvelopeV1 =
        serde_json::from_value(wrapping.envelope)?;
    let wrapping_aad = umbra_crypto::AadV1::vault_key_wrapping(vault_id.to_string());
    let vault_key =
        umbra_crypto::unwrap_vault_key(&unlocked.private_key, &wrapping_aad, &wrapping_envelope)?;
    let item_id = uuid::Uuid::new_v4();
    let plaintext = crate::item_plaintext::build_secret_bundle(&project_env, &key, &value);
    let plaintext_json = serde_json::to_vec(&plaintext)?;
    let kind = ItemKind::EnvBundle;
    let kind_name = item_kind_name(&kind);
    let aad = umbra_crypto::AadV1::item(vault_id.to_string(), item_id.to_string(), 1, kind_name.clone());
    let crypto = umbra_crypto::encrypt_item(&vault_key, aad, &plaintext_json)?;
    let response: Value = client
        .post(
            &format!("/api/v1/vaults/{vault_id}/items"),
            &CreateItemRequest {
                protocol_version: PROTOCOL_VERSION,
                item_id: Some(item_id),
                vault_id,
                kind,
                envelope: serde_json::json!({ "kind": kind_name, "crypto": crypto }),
            },
        )
        .await?;
    print_json(&response)
}
```

- [ ] **Step 5: Implement `secret get` from cached item scan**

In `commands.rs`, add:

```rust
Command::Secret(SecretCommand::Get {
    project_env,
    key,
    vault_id,
}) => {
    let cache = crate::cache::LocalCache::open(&config.active_profile)?;
    let profile = active_profile(&config)?;
    let user_id = profile.user_id.ok_or(CliError::MissingCryptoMaterial)?;
    let wrapping = cache
        .latest_key_wrapping(vault_id, user_id)?
        .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
    let password = rpassword::prompt_password("Master password: ")?;
    let unlocked = crate::crypto_state::load_unlocked_profile(
        profile,
        &umbra_crypto::MasterPassword::new(password.into_bytes()),
    )?;
    let wrapping_envelope: umbra_crypto::VaultKeyWrappingEnvelopeV1 =
        serde_json::from_value(wrapping.envelope)?;
    let wrapping_aad = umbra_crypto::AadV1::vault_key_wrapping(vault_id.to_string());
    let vault_key =
        umbra_crypto::unwrap_vault_key(&unlocked.private_key, &wrapping_aad, &wrapping_envelope)?;

    for revision in cache.list_latest_item_revisions(vault_id)? {
        let kind_name = revision
            .envelope
            .get("kind")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if kind_name != "env_bundle" {
            continue;
        }
        let Some(envelope_value) = revision.envelope.get("crypto").cloned() else {
            continue;
        };
        let envelope: umbra_crypto::CryptoEnvelopeV1 = serde_json::from_value(envelope_value)?;
        let aad = umbra_crypto::AadV1::item(
            vault_id.to_string(),
            revision.item_id.to_string(),
            revision.revision,
            kind_name.to_owned(),
        );
        let plaintext = umbra_crypto::decrypt_item(&vault_key, &aad, &envelope)?;
        let item: umbra_core::ItemPlaintextV1 = serde_json::from_slice(&plaintext)?;
        if item.title == project_env {
            if let Some(field) = item.fields.iter().find(|field| field.name == key) {
                println!("{}", field.value);
                return Ok(());
            }
        }
    }
    Err(CliError::Input("secret not found"))
}
```

- [ ] **Step 6: Run CLI tests**

Run:

```bash
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): add secret set get commands"
```

---

### Task 13: Document Real CLI Flow

**Files:**
- Modify: `README.md`
- Modify: `docs/crypto.md`
- Test: `cargo fmt --all --check`

- [ ] **Step 1: Update README happy path**

Add this section to `README.md`:

```markdown
## Current CLI Happy Path

```bash
umbra register --email miguel@example.com
umbra login --email miguel@example.com
umbra vault create Personal
umbra sync run --vault <vault-id> --force-full
umbra secret set pulzar/dev DATABASE_URL "postgres://user:pass@localhost:5432/app" --vault-id <vault-id>
umbra sync run --vault <vault-id>
umbra secret get pulzar/dev DATABASE_URL --vault-id <vault-id>
```

The CLI encrypts item plaintext locally before upload. The server receives only JSON envelopes and key wrappings. The local SQLite cache stores encrypted envelopes and wrapped vault keys, not plaintext fields.
```

- [ ] **Step 2: Update crypto docs**

Add this section to `docs/crypto.md`:

```markdown
## CLI Crypto MVP

The CLI registration flow generates:

- a random `UserSecretKey`;
- an X25519 user keypair;
- Argon2id KDF params per profile;
- an encrypted user private key envelope.

The profile stores the public key, encrypted private key envelope, KDF params, and user secret key. This is acceptable for the current developer MVP, but before a production release the `UserSecretKey` should be shown as an emergency kit and protected by OS keychain or equivalent local secret storage instead of plain TOML.

Vault creation generates a random `VaultKey` and wraps it for the user's public key. Item creation serializes `ItemPlaintextV1`, encrypts it with a key derived from the vault key and item AAD, and uploads only the envelope.
```

- [ ] **Step 3: Run docs-safe checks**

Run:

```bash
cargo fmt --all --check
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/crypto.md
git commit -m "docs(cli): document real crypto flow"
```

---

### Task 14: Full Verification and Push

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run full formatting**

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
git status --short
git push origin main
```

Expected: push succeeds.

---

## Self-Review

Spec coverage:

- Real client-side item encryption: covered by Tasks 3, 9, 10, and 11.
- Vault key generated per vault: covered by Tasks 5 and 6.
- Owner vault key wrapping: covered by Tasks 5, 6, and 8.
- Secret set/get UX: covered by Task 12.
- Cache integration: covered by Tasks 8, 11, and 12.
- Server remains zero-knowledge: server changes only accept client-supplied UUIDs and still store JSON envelopes.
- Documentation: covered by Task 13.

Gaps deliberately left for later:

- Shared vault member invite/wrapping flow.
- Updating an existing `env_bundle` instead of creating a new item per `secret set`.
- Local secret key protection via OS keychain.
- Non-interactive unlock/session cache.
- Web UI.

Placeholder scan:

- No task contains `TBD`, `TODO`, `implement later`, or "add appropriate".
- Every code-changing step includes concrete code or exact struct/command edits.

Type consistency:

- `CreateVaultRequest.vault_id: Option<VaultId>` is used consistently by protocol, server, and CLI.
- `CreateItemRequest.item_id: Option<ItemId>` is used consistently by protocol, server, and CLI.
- `CachedKeyWrapping` is made production-visible before decrypt flows need it.
- `item_kind_name` gives stable AAD kind strings for encrypt and decrypt.
