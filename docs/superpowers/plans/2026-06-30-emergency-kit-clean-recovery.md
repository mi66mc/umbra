# Emergency Kit Clean Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow a clean machine with no trusted local profile crypto to recover device trust using OPAQUE login plus an exported emergency kit.

**Architecture:** Keep recovery zero-knowledge: the emergency kit contains the account public key, KDF params, and user secret key, but not the master password, user private key plaintext, vault keys, item plaintext, or reusable session tokens. A new pending-device login stores the server-provided encrypted user private key locally; `device recover --emergency-kit <path>` combines that encrypted envelope with the emergency kit and prompted master password to decrypt the account private key locally, answer the server recovery challenge, and then save the account crypto material in the profile only after trust succeeds.

**Tech Stack:** Rust 1.88, Clap, serde/serde_json, existing `umbra-cli`, `umbra-crypto`, `umbra-protocol`, signed HTTP sessions, current recovery challenge API.

---

## Current Gap

The server already supports:

- pending device creation through OPAQUE login;
- recovery challenge creation;
- encrypted challenge to account public key;
- `recover-trust` challenge response;
- marking the pending device trusted.

The CLI currently cannot recover on a clean machine because `device recover` calls `load_unlocked_profile(profile, password)`, which requires `profile.user_secret_key`, `profile.kdf_params`, and `profile.client_public_key` to already exist. That is exactly what a clean recovered profile lacks.

---

## File Structure

- `crates/umbra-cli/src/crypto_state.rs`
  - Owns `EmergencyKitV1` and all account-crypto unlock helpers.
  - Adds safe parsing/export validation.
- `crates/umbra-cli/src/main.rs`
  - Adds `umbra emergency-kit export`.
  - Adds `--emergency-kit <path>` to `umbra device recover`.
- `crates/umbra-cli/src/commands.rs`
  - Saves encrypted private key during `login --new-device`.
  - Exports emergency kit from an existing trusted profile.
  - Recovers clean profiles from emergency kit.
- `crates/umbra-cli/src/tests.rs`
  - Adds command parser tests.
- `README.md`, `docs/architecture.md`, `docs/crypto.md`, `docs/protocol.md`
  - Documents the actual clean-machine flow and removes stale wording that says the flow is planned.

No server API changes are required in this plan.

---

### Task 1: Add Emergency Kit Type And Recovery Unlock Helper

**Files:**
- Modify: `crates/umbra-cli/src/crypto_state.rs`

- [ ] **Step 1: Write failing tests**

Add these tests inside `#[cfg(test)] mod tests` in `crates/umbra-cli/src/crypto_state.rs`:

```rust
#[test]
fn emergency_kit_roundtrips_without_private_key_material() {
    let password = MasterPassword::new("correct horse battery staple");
    let account_crypto = NewAccountCrypto::generate(&password).unwrap();

    let kit = EmergencyKitV1::from_account_crypto(
        Some("miguel@example.com".to_owned()),
        &account_crypto,
    );
    let encoded = serde_json::to_string_pretty(&kit).unwrap();

    assert!(encoded.contains("\"version\": 1"));
    assert!(encoded.contains("miguel@example.com"));
    assert!(encoded.contains(&account_crypto.public_key.to_base64url()));
    assert!(encoded.contains(&account_crypto.user_secret_key.to_base64url()));
    assert!(!encoded.contains("encrypted_private_key"));
    assert!(!encoded.contains("private_key"));

    let decoded: EmergencyKitV1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, kit);
}

#[test]
fn unlock_profile_with_emergency_kit_works_without_profile_secret_key() {
    let password = MasterPassword::new("correct horse battery staple");
    let account_crypto = NewAccountCrypto::generate(&password).unwrap();
    let kit = EmergencyKitV1::from_account_crypto(None, &account_crypto);
    let clean_profile = ProfileConfig {
        encrypted_user_private_key: Some(
            serde_json::to_value(account_crypto.encrypted_private_key.clone()).unwrap(),
        ),
        user_secret_key: None,
        kdf_params: None,
        client_public_key: None,
        ..ProfileConfig::default()
    };

    let unlocked = unlock_profile_with_emergency_kit(&clean_profile, &password, &kit).unwrap();

    assert_eq!(unlocked.public_key, account_crypto.public_key);
    assert_eq!(
        unlocked.private_key.to_base64url(),
        account_crypto.unlock(&password).unwrap().private_key.to_base64url()
    );
}

#[test]
fn unlock_profile_with_emergency_kit_rejects_wrong_password() {
    let password = MasterPassword::new("correct horse battery staple");
    let wrong_password = MasterPassword::new("wrong horse battery staple");
    let account_crypto = NewAccountCrypto::generate(&password).unwrap();
    let kit = EmergencyKitV1::from_account_crypto(None, &account_crypto);
    let clean_profile = ProfileConfig {
        encrypted_user_private_key: Some(
            serde_json::to_value(account_crypto.encrypted_private_key.clone()).unwrap(),
        ),
        ..ProfileConfig::default()
    };

    assert!(unlock_profile_with_emergency_kit(&clean_profile, &wrong_password, &kit).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p umbra-cli emergency_kit
```

Expected: fail because `EmergencyKitV1` and `unlock_profile_with_emergency_kit` do not exist.

- [ ] **Step 3: Add imports**

In `crates/umbra-cli/src/crypto_state.rs`, extend the existing imports:

```rust
use serde::{Deserialize, Serialize};
```

- [ ] **Step 4: Add `EmergencyKitV1`**

Add this near `UnlockedAccountCrypto`:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EmergencyKitV1 {
    pub(crate) version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<String>,
    pub(crate) account_public_key: String,
    pub(crate) user_secret_key: String,
    pub(crate) kdf_params: Argon2idParams,
}

impl EmergencyKitV1 {
    pub(crate) fn from_account_crypto(
        email: Option<String>,
        account_crypto: &NewAccountCrypto,
    ) -> Self {
        Self {
            version: 1,
            email,
            account_public_key: account_crypto.public_key.to_base64url(),
            user_secret_key: account_crypto.user_secret_key.to_base64url(),
            kdf_params: account_crypto.kdf_params.clone(),
        }
    }

    pub(crate) fn from_profile(profile: &ProfileConfig) -> Result<Self, CliError> {
        let account_public_key = profile
            .client_public_key
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?;
        let user_secret_key = profile
            .user_secret_key
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?;
        let kdf_params = profile
            .kdf_params
            .clone()
            .ok_or(CliError::MissingCryptoMaterial)?;

        Ok(Self {
            version: 1,
            email: profile.email.clone(),
            account_public_key,
            user_secret_key,
            kdf_params,
        })
    }
}
```

- [ ] **Step 5: Add recovery unlock helper**

Add this below `load_unlocked_profile`:

```rust
pub(crate) fn unlock_profile_with_emergency_kit(
    profile: &ProfileConfig,
    password: &MasterPassword,
    emergency_kit: &EmergencyKitV1,
) -> Result<UnlockedAccountCrypto, CliError> {
    if emergency_kit.version != 1 {
        return Err(CliError::Input("unsupported emergency kit version"));
    }

    let public_key = UserPublicKey::from_base64url(&emergency_kit.account_public_key)?;
    let user_secret_key = UserSecretKey::from_base64url(&emergency_kit.user_secret_key)?;
    let encrypted_private_key = profile
        .encrypted_user_private_key
        .clone()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| serde_json::from_value(value).map_err(CliError::from))?;

    let account_crypto = NewAccountCrypto {
        public_key,
        user_secret_key,
        kdf_params: emergency_kit.kdf_params.clone(),
        encrypted_private_key,
    };

    account_crypto.unlock(password)
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p umbra-cli emergency_kit
```

Expected: the 3 emergency kit tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/crypto_state.rs
git commit -m "feat(cli): add emergency kit crypto state"
```

---

### Task 2: Add CLI Surface For Emergency Kit Export And Recover Input

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Write failing parser tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_emergency_kit_export_command() {
    let cli = Cli::parse_from([
        "umbra",
        "emergency-kit",
        "export",
        "--output",
        "umbra-emergency-kit.json",
    ]);

    let Command::EmergencyKit(crate::EmergencyKitCommand::Export { output }) = cli.command else {
        panic!("expected emergency-kit export command");
    };

    assert_eq!(output.as_deref(), Some("umbra-emergency-kit.json"));
}
```

Update `parses_device_commands` with this additional assertion:

```rust
let cli = Cli::parse_from([
    "umbra",
    "device",
    "recover",
    "--device-id",
    "00000000-0000-0000-0000-000000000001",
    "--emergency-kit",
    "umbra-emergency-kit.json",
]);
assert!(matches!(
    cli.command,
    Command::Device(DeviceCommand::Recover {
        device_id: Some(_),
        emergency_kit: Some(path),
    }) if path == std::path::PathBuf::from("umbra-emergency-kit.json")
));
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p umbra-cli parses_emergency_kit_export_command
cargo test -p umbra-cli parses_device_commands
```

Expected: fail because `EmergencyKitCommand`, `Command::EmergencyKit`, and `DeviceCommand::Recover.emergency_kit` do not exist.

- [ ] **Step 3: Add `PathBuf` import**

In `crates/umbra-cli/src/main.rs`, add:

```rust
use std::path::PathBuf;
```

- [ ] **Step 4: Add command enum**

In `Command`, add:

```rust
#[command(subcommand)]
EmergencyKit(EmergencyKitCommand),
```

Below `CacheCommand`, add:

```rust
#[derive(Debug, Subcommand)]
pub enum EmergencyKitCommand {
    Export {
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
```

- [ ] **Step 5: Extend device recover command**

Replace:

```rust
Recover {
    #[arg(long)]
    device_id: Option<DeviceId>,
},
```

with:

```rust
Recover {
    #[arg(long)]
    device_id: Option<DeviceId>,
    #[arg(long)]
    emergency_kit: Option<PathBuf>,
},
```

- [ ] **Step 6: Allow config load for emergency kit export**

No change is needed for `load_config_for_command`; emergency kit export requires an existing profile and should fail if config is unreadable.

- [ ] **Step 7: Run parser tests**

Run:

```bash
cargo test -p umbra-cli parses_emergency_kit_export_command
cargo test -p umbra-cli parses_device_commands
```

Expected: pass.

- [ ] **Step 8: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): add emergency kit commands"
```

---

### Task 3: Save Clean-Device Login Crypto Metadata

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Write failing unit test**

In `#[cfg(test)] mod tests` in `crates/umbra-cli/src/commands.rs`, add:

```rust
#[test]
fn save_pending_login_crypto_material_stores_encrypted_private_key() {
    let mut profile = crate::config::ProfileConfig::default();
    let encrypted_private_key = serde_json::json!({
        "version": 1,
        "suite": "UMBRA_XCHACHA20POLY1305_HKDFSHA256_V1",
        "nonce": "nonce",
        "aad": "aad",
        "ciphertext": "ciphertext"
    });

    save_pending_login_crypto_material(&mut profile, encrypted_private_key.clone());

    assert_eq!(
        profile.encrypted_user_private_key.as_ref(),
        Some(&encrypted_private_key)
    );
    assert_eq!(profile.user_secret_key, None);
    assert_eq!(profile.kdf_params, None);
    assert_eq!(profile.client_public_key, None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli save_pending_login_crypto_material
```

Expected: fail because `save_pending_login_crypto_material` does not exist.

- [ ] **Step 3: Add helper**

In `crates/umbra-cli/src/commands.rs`, near the other private helper functions, add:

```rust
fn save_pending_login_crypto_material(
    profile: &mut crate::config::ProfileConfig,
    encrypted_private_key: serde_json::Value,
) {
    profile.encrypted_user_private_key = Some(encrypted_private_key);
    profile.client_public_key = None;
    profile.kdf_params = None;
    profile.user_secret_key = None;
}
```

- [ ] **Step 4: Use helper in `login --new-device`**

In the `Command::Login { new_device: true, .. }` branch, after:

```rust
profile_config.legacy_session_token = response.session_token;
```

add:

```rust
save_pending_login_crypto_material(profile_config, response.encrypted_private_key);
```

This stores the server-provided encrypted private key envelope for later local emergency-kit decrypt, while intentionally leaving the secret key/KDF/public key absent until recovery succeeds.

- [ ] **Step 5: Run test**

Run:

```bash
cargo test -p umbra-cli save_pending_login_crypto_material
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "fix(cli): persist pending recovery envelope"
```

---

### Task 4: Implement Emergency Kit Export

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Write failing tests**

In `#[cfg(test)] mod tests` in `crates/umbra-cli/src/commands.rs`, add:

```rust
#[test]
fn emergency_kit_from_profile_omits_encrypted_private_key() {
    let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&MasterPassword::new(
        "correct horse battery staple",
    ))
    .unwrap();
    let profile = crate::config::ProfileConfig {
        email: Some("miguel@example.com".to_owned()),
        client_public_key: Some(account_crypto.public_key.to_base64url()),
        encrypted_user_private_key: Some(
            serde_json::to_value(account_crypto.encrypted_private_key).unwrap(),
        ),
        kdf_params: Some(account_crypto.kdf_params.clone()),
        user_secret_key: Some(account_crypto.user_secret_key.to_base64url()),
        ..crate::config::ProfileConfig::default()
    };

    let kit = emergency_kit_json_from_profile(&profile).unwrap();

    assert!(kit.contains("miguel@example.com"));
    assert!(kit.contains(&account_crypto.public_key.to_base64url()));
    assert!(kit.contains(&account_crypto.user_secret_key.to_base64url()));
    assert!(!kit.contains("encrypted_private_key"));
    assert!(!kit.contains("private_key"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli emergency_kit_from_profile_omits_encrypted_private_key
```

Expected: fail because `emergency_kit_json_from_profile` does not exist.

- [ ] **Step 3: Import command enum**

At the top of `crates/umbra-cli/src/commands.rs`, extend the command imports:

```rust
EmergencyKitCommand,
```

- [ ] **Step 4: Add command match arm**

In `run`, near other top-level command arms, add:

```rust
Command::EmergencyKit(EmergencyKitCommand::Export { output }) => {
    let profile = active_profile(&config)?;
    let encoded = emergency_kit_json_from_profile(profile)?;
    if let Some(path) = output {
        std::fs::write(&path, encoded)?;
        println!("emergency kit written: {}", path.display());
        Ok(())
    } else {
        println!("{encoded}");
        Ok(())
    }
}
```

- [ ] **Step 5: Add helper**

Add near private helper functions:

```rust
fn emergency_kit_json_from_profile(
    profile: &crate::config::ProfileConfig,
) -> Result<String, CliError> {
    let kit = crate::crypto_state::EmergencyKitV1::from_profile(profile)?;
    serde_json::to_string_pretty(&kit).map_err(CliError::from)
}
```

- [ ] **Step 6: Run test**

Run:

```bash
cargo test -p umbra-cli emergency_kit_from_profile_omits_encrypted_private_key
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): export emergency kit"
```

---

### Task 5: Recover Device Trust From Emergency Kit

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`

- [ ] **Step 1: Write failing helper test**

In `#[cfg(test)] mod tests` in `crates/umbra-cli/src/commands.rs`, add:

```rust
#[test]
fn apply_recovered_emergency_kit_material_saves_profile_crypto() {
    let account_crypto = crate::crypto_state::NewAccountCrypto::generate(&MasterPassword::new(
        "correct horse battery staple",
    ))
    .unwrap();
    let kit =
        crate::crypto_state::EmergencyKitV1::from_account_crypto(None, &account_crypto);
    let mut profile = crate::config::ProfileConfig {
        pending_approval_code: Some("UMBRA-ABCD-1234".to_owned()),
        legacy_session_token: Some("pending-bearer".to_owned()),
        session_id: Some(uuid::Uuid::new_v4()),
        encrypted_user_private_key: Some(
            serde_json::to_value(account_crypto.encrypted_private_key.clone()).unwrap(),
        ),
        ..crate::config::ProfileConfig::default()
    };

    apply_recovered_emergency_kit_material(&mut profile, &kit).unwrap();

    assert_eq!(
        profile.client_public_key.as_deref(),
        Some(account_crypto.public_key.to_base64url().as_str())
    );
    assert_eq!(
        profile.user_secret_key.as_deref(),
        Some(account_crypto.user_secret_key.to_base64url().as_str())
    );
    assert_eq!(profile.kdf_params.as_ref(), Some(&account_crypto.kdf_params));
    assert_eq!(profile.pending_approval_code, None);
    assert_eq!(profile.legacy_session_token, None);
    assert_eq!(profile.session_id, None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbra-cli apply_recovered_emergency_kit_material
```

Expected: fail because the helper does not exist.

- [ ] **Step 3: Add helper to read kit file**

Add:

```rust
fn read_emergency_kit(path: &std::path::Path) -> Result<crate::crypto_state::EmergencyKitV1, CliError> {
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(CliError::from)
}
```

- [ ] **Step 4: Add helper to save recovered material**

Add:

```rust
fn apply_recovered_emergency_kit_material(
    profile: &mut crate::config::ProfileConfig,
    kit: &crate::crypto_state::EmergencyKitV1,
) -> Result<(), CliError> {
    if kit.version != 1 {
        return Err(CliError::Input("unsupported emergency kit version"));
    }

    profile.client_public_key = Some(kit.account_public_key.clone());
    profile.user_secret_key = Some(kit.user_secret_key.clone());
    profile.kdf_params = Some(kit.kdf_params.clone());
    profile.pending_approval_code = None;
    profile.legacy_session_token = None;
    profile.session_id = None;
    Ok(())
}
```

- [ ] **Step 5: Update `DeviceCommand::Recover` match pattern**

Replace:

```rust
Command::Device(DeviceCommand::Recover { device_id }) => {
```

with:

```rust
Command::Device(DeviceCommand::Recover {
    device_id,
    emergency_kit,
}) => {
```

- [ ] **Step 6: Use emergency kit in recovery**

Inside the recover arm, replace:

```rust
let password = rpassword::prompt_password("Master password: ")?;
let unlocked = crate::crypto_state::load_unlocked_profile(
    profile,
    &MasterPassword::new(password.into_bytes()),
)?;
```

with:

```rust
let emergency_kit = match emergency_kit {
    Some(path) => read_emergency_kit(&path)?,
    None => {
        return Err(CliError::Input(
            "pass --emergency-kit <path> for clean-device recovery",
        ));
    }
};
let password = rpassword::prompt_password("Master password: ")?;
let master_password = MasterPassword::new(password.into_bytes());
let unlocked = crate::crypto_state::unlock_profile_with_emergency_kit(
    profile,
    &master_password,
    &emergency_kit,
)?;
```

- [ ] **Step 7: Save recovered crypto material only after server trust succeeds**

After:

```rust
let recovered: RecoverTrustResponse = client
    .post(
        &format!("/api/v1/devices/{device_id}/recover-trust"),
        &RecoverTrustRequest {
            protocol_version: PROTOCOL_VERSION,
            challenge_id: challenge.challenge_id,
            challenge_response,
        },
    )
    .await?;
```

replace:

```rust
profile.pending_approval_code = None;
```

with:

```rust
apply_recovered_emergency_kit_material(profile, &emergency_kit)?;
```

- [ ] **Step 8: Run helper test**

Run:

```bash
cargo test -p umbra-cli apply_recovered_emergency_kit_material
```

Expected: pass.

- [ ] **Step 9: Run CLI parser and crypto state tests**

Run:

```bash
cargo test -p umbra-cli emergency_kit
cargo test -p umbra-cli parses_device_commands
```

Expected: pass.

- [ ] **Step 10: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "feat(cli): recover device with emergency kit"
```

---

### Task 6: Documentation And Happy Path

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/crypto.md`
- Modify: `docs/protocol.md`

- [ ] **Step 1: Update README multi-device section**

Replace the current note:

```txt
`device recover` uses the protocol recovery challenge, but the current CLI expects the profile to already have enough local account crypto material to decrypt the challenge. A clean-machine emergency-kit import command is planned separately.
```

with:

```txt
`device recover` supports clean-machine recovery when the user has the emergency kit exported from a trusted profile.

Export the kit once from a trusted device and store it offline:

```bash
umbra emergency-kit export --output umbra-emergency-kit.json
```

Recover on a clean device:

```bash
umbra login --profile recovered --email miguel@example.com --new-device --device-name "Recovered laptop"
umbra device recover --emergency-kit umbra-emergency-kit.json
umbra login --profile recovered
```

The emergency kit contains the account public key, KDF params, and user secret key. It does not contain the master password, user private key plaintext, vault keys, item plaintext, or session tokens. Anyone with the emergency kit and master password can recover the account, so store it offline.
```

- [ ] **Step 2: Update `docs/architecture.md`**

In the “Secret Key UX” section, replace the clean-device sentence with:

```txt
- New device with no trusted device available: user enters password, imports the emergency kit, decrypts the server-provided encrypted user private key locally, and completes a recovery challenge.
```

- [ ] **Step 3: Update `docs/crypto.md`**

Replace the stale production note about plain TOML with:

```txt
The CLI can export an emergency kit containing `user_secret_key`, KDF params, and the account public key. The emergency kit must be stored offline. The normal profile may still cache account crypto material for developer-MVP usability, but clean-device recovery should use the emergency kit path instead of relying on a previous local profile.
```

- [ ] **Step 4: Update `docs/protocol.md`**

Replace:

```txt
The current CLI recovery path requires the profile to already have enough local account crypto material to decrypt the challenge. A clean-device emergency-kit import flow is planned separately.
```

with:

```txt
The CLI clean-device recovery path gets account public key, KDF params, and user secret key from the emergency kit, while the encrypted user private key comes from the OPAQUE login response. The challenge is decrypted locally and the plaintext challenge response is sent to `recover-trust`.
```

- [ ] **Step 5: Run docs-related tests**

Run:

```bash
cargo test -p umbra-cli emergency_kit
cargo test -p umbra-cli parses_emergency_kit_export_command
cargo test -p umbra-cli parses_device_commands
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/architecture.md docs/crypto.md docs/protocol.md
git commit -m "docs(cli): document emergency kit recovery"
```

---

### Task 7: Final Verification

**Files:**
- No new files.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit 0.

- [ ] **Step 2: Check workspace**

Run:

```bash
cargo check --workspace
```

Expected: exit 0.

- [ ] **Step 3: Test workspace**

Run:

```bash
cargo test --workspace
```

Expected: exit 0 with all tests passing.

- [ ] **Step 4: Manual smoke test with SQLite server**

Run in one terminal:

```powershell
$env:UMBRA__DATABASE__BACKEND="sqlite"
$env:UMBRA__DATABASE__URL="sqlite://./umbra-emergency-smoke.db?mode=rwc"
$env:UMBRA__MIGRATIONS__AUTO_MIGRATE="true"
$env:UMBRA__AUTH__OPAQUE__ALLOW_EPHEMERAL_SETUP="true"
cargo run -p umbra-server -- serve
```

Run in another terminal using a temporary config:

```powershell
$env:UMBRA_CONFIG="$PWD\\.tmp\\emergency-config.toml"
cargo run -p umbra-cli -- register --server http://127.0.0.1:8080 --email recovery@example.com --profile primary --device-name "Primary"
cargo run -p umbra-cli -- emergency-kit export --output .tmp\\umbra-emergency-kit.json
cargo run -p umbra-cli -- login --profile recovered --email recovery@example.com --new-device --device-name "Recovered"
cargo run -p umbra-cli -- device recover --emergency-kit .tmp\\umbra-emergency-kit.json
cargo run -p umbra-cli -- login --profile recovered
cargo run -p umbra-cli -- device list
```

Expected:

- register succeeds;
- emergency kit file is created;
- recovered profile starts as pending;
- `device recover` prompts for the master password, completes challenge response, clears the pending bearer token, and prints recovered device trust;
- `login --profile recovered` creates a normal signed session for the now-trusted device;
- `device list` works from the recovered profile after the post-recovery login.

- [ ] **Step 5: Commit any final fixes**

If final verification required code/doc edits:

```bash
git add <changed-files>
git commit -m "fix(cli): polish emergency kit recovery"
```

If no files changed, do not create a commit.

---

## Self-Review Notes

- Spec coverage: this plan implements clean-machine recovery, not shared vault invites or key rotation.
- Server changes: none required because recovery challenge APIs already exist.
- Zero-knowledge boundary: preserved; emergency kit and recovery helpers never send user secret key, account KEK, user private key plaintext, vault keys, or item plaintext to the server.
- Main security tradeoff: anyone with the emergency kit and master password can recover a device. The docs make offline storage mandatory.
