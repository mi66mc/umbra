# Local Unlock Keychain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `umbra unlock`, `umbra lock`, and `umbra status` so the CLI can reuse locally unlocked vault keys without prompting for the master password on every item/secret command.

**Architecture:** The CLI will store an encrypted local unlock state file per profile under the existing local data directory. The file contains the user private key and selected vault keys encrypted with `XChaCha20-Poly1305`; the encryption key is random and stored in the OS keychain via the `keyring` crate. Commands first try the unlocked local state, then fall back to the current master-password prompt path.

**Tech Stack:** Rust, clap, serde/serde_json, chrono, keyring, existing `umbra-crypto` XChaCha20-Poly1305 envelope code, existing rusqlite CLI cache.

---

## Scope

This plan implements local unlock state only. It does not add browser/desktop keychain UX, team invites, recovery keys, or full SQLite database encryption.

The zero-knowledge boundary remains unchanged:

- server never receives plaintext secrets;
- SQLite cache still stores encrypted item envelopes and wrapped vault keys;
- local unlock state stores decrypted key material only after encrypting it with a random local key held in the OS keychain;
- `umbra lock` removes both the keychain secret and encrypted unlock state file.

## File Structure

- Modify `crates/umbra-crypto/src/lib.rs`
  - Add `LocalUnlockKey`.
  - Add `AadV1::local_unlock_state`.
  - Add `encrypt_local_unlock_state` and `decrypt_local_unlock_state`.
  - Add tests for roundtrip and AAD tamper failure.

- Modify `Cargo.toml`
  - Add workspace dependency `keyring = "3"`.

- Modify `crates/umbra-cli/Cargo.toml`
  - Add `keyring.workspace = true`.

- Create `crates/umbra-cli/src/unlock_store.rs`
  - Owns encrypted unlock state file format.
  - Owns production keychain adapter and test in-memory key store.
  - Exposes `UnlockStore::save`, `UnlockStore::load`, `UnlockStore::clear`, and `UnlockStore::status`.

- Modify `crates/umbra-cli/src/main.rs`
  - Register `mod unlock_store;`.
  - Add top-level `unlock`, `lock`, and `status` commands.

- Modify `crates/umbra-cli/src/commands.rs`
  - Implement unlock/lock/status command handling.
  - Update vault key resolution to check unlock state before prompting for master password.
  - Update vault creation to wrap owner vault key with the profile public key directly, avoiding unnecessary password prompt.

- Modify `crates/umbra-cli/src/error.rs`
  - Add keychain error conversion.
  - Add unlock-state specific error messages.

- Modify `crates/umbra-cli/src/tests.rs`
  - Add parser tests for unlock/lock/status.

- Modify `README.md`
  - Document the new unlock flow and fallback behavior.

- Modify `docs/threat-model.md`
  - Document the OS keychain trust assumption for local unlock state.

---

### Task 1: Add Local Unlock Crypto Primitives

**Files:**
- Modify: `crates/umbra-crypto/src/lib.rs`
- Test: `crates/umbra-crypto/src/lib.rs`

- [ ] **Step 1: Write failing crypto tests**

Add these tests inside the existing `#[cfg(test)] mod tests` in `crates/umbra-crypto/src/lib.rs`:

```rust
#[test]
fn local_unlock_state_encrypt_decrypt_roundtrip() {
    let key = LocalUnlockKey::generate();
    let aad = AadV1::local_unlock_state("personal", "device-1");
    let plaintext = br#"{"version":1,"vault_keys":{}}"#;

    let envelope = encrypt_local_unlock_state(&key, aad.clone(), plaintext).unwrap();
    let decrypted = decrypt_local_unlock_state(&key, &aad, &envelope).unwrap();

    assert_eq!(decrypted, plaintext);
    assert_eq!(LocalUnlockKey::from_base64url(&key.to_base64url()).unwrap(), key);
}

#[test]
fn local_unlock_state_decrypt_fails_with_wrong_aad() {
    let key = LocalUnlockKey::generate();
    let aad = AadV1::local_unlock_state("personal", "device-1");
    let wrong_aad = AadV1::local_unlock_state("personal", "device-2");

    let envelope = encrypt_local_unlock_state(&key, aad, b"secret").unwrap();

    assert!(decrypt_local_unlock_state(&key, &wrong_aad, &envelope).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p umbra-crypto local_unlock_state
```

Expected: FAIL with errors similar to:

```txt
cannot find type `LocalUnlockKey` in this scope
cannot find function `encrypt_local_unlock_state` in this scope
no function or associated item named `local_unlock_state` found for struct `AadV1`
```

- [ ] **Step 3: Add `LocalUnlockKey`**

In `crates/umbra-crypto/src/lib.rs`, add this after `pub struct AccountKek` and its `Debug` impl:

```rust
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalUnlockKey([u8; KEY_LEN]);

impl LocalUnlockKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    fn as_key(&self) -> &Key {
        Key::from_slice(&self.0)
    }

    pub fn to_base64url(&self) -> String {
        encode_b64(&self.0)
    }

    pub fn from_base64url(encoded: &str) -> Result<Self, CryptoError> {
        Ok(Self(decode_array(encoded)?))
    }
}

impl std::fmt::Debug for LocalUnlockKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalUnlockKey([redacted])")
    }
}
```

- [ ] **Step 4: Add `VaultKey::from_base64url`**

In `impl VaultKey`, add this method after `to_base64url`:

```rust
pub fn from_base64url(encoded: &str) -> Result<Self, CryptoError> {
    Ok(Self(decode_array(encoded)?))
}
```

- [ ] **Step 5: Add local unlock AAD**

In `impl AadV1`, add:

```rust
pub fn local_unlock_state(profile: impl Into<String>, device_id: impl Into<String>) -> Self {
    Self {
        app: "umbra".to_owned(),
        purpose: "local_unlock_state".to_owned(),
        schema: 1,
        vault_id: profile.into(),
        item_id: Some(device_id.into()),
        revision: None,
        kind: None,
    }
}
```

- [ ] **Step 6: Add local unlock encrypt/decrypt functions**

Add these public functions after `decrypt_user_private_key`:

```rust
pub fn encrypt_local_unlock_state(
    key: &LocalUnlockKey,
    aad: AadV1,
    plaintext: &[u8],
) -> Result<CryptoEnvelopeV1, CryptoError> {
    encrypt_with_key(key.as_key(), aad, plaintext)
}

pub fn decrypt_local_unlock_state(
    key: &LocalUnlockKey,
    expected_aad: &AadV1,
    envelope: &CryptoEnvelopeV1,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_with_key(key.as_key(), expected_aad, envelope)
}
```

- [ ] **Step 7: Run crypto tests**

Run:

```bash
cargo test -p umbra-crypto local_unlock_state
cargo clippy -p umbra-crypto --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/umbra-crypto/src/lib.rs
git commit -m "feat(crypto): add local unlock envelopes"
```

---

### Task 2: Add CLI Unlock Store Module

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/umbra-cli/Cargo.toml`
- Modify: `crates/umbra-cli/src/error.rs`
- Create: `crates/umbra-cli/src/unlock_store.rs`
- Modify: `crates/umbra-cli/src/main.rs`

- [ ] **Step 1: Add dependencies**

In root `Cargo.toml`, add this under `[workspace.dependencies]`:

```toml
keyring = "3"
```

In `crates/umbra-cli/Cargo.toml`, add this under `[dependencies]`:

```toml
keyring.workspace = true
```

- [ ] **Step 2: Add error variants**

In `crates/umbra-cli/src/error.rs`, add these variants before `ServerStatus`:

```rust
#[error("keychain error: {0}")]
Keyring(#[from] keyring::Error),
#[error("profile is locked; run `umbra unlock` or enter the master password when prompted")]
Locked,
#[error("local unlock state is expired; run `umbra unlock` again")]
UnlockExpired,
```

- [ ] **Step 3: Register module**

In `crates/umbra-cli/src/main.rs`, add:

```rust
mod unlock_store;
```

Place it with the other module declarations:

```rust
mod sync;
mod unlock_store;
```

- [ ] **Step 4: Create failing unlock store tests**

Create `crates/umbra-cli/src/unlock_store.rs` with only this test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use umbra_crypto::{LocalUnlockKey, UserPrivateKey, VaultKey};

    #[derive(Clone, Default)]
    struct MemoryKeyStore {
        values: Arc<Mutex<HashMap<String, String>>>,
    }

    impl UnlockKeyStore for MemoryKeyStore {
        fn set_unlock_key(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError> {
            self.values
                .lock()
                .unwrap()
                .insert(profile.to_owned(), key.to_base64url());
            Ok(())
        }

        fn get_unlock_key(&self, profile: &str) -> Result<Option<LocalUnlockKey>, CliError> {
            self.values
                .lock()
                .unwrap()
                .get(profile)
                .map(|value| LocalUnlockKey::from_base64url(value).map_err(CliError::from))
                .transpose()
        }

        fn clear_unlock_key(&self, profile: &str) -> Result<(), CliError> {
            self.values.lock().unwrap().remove(profile);
            Ok(())
        }
    }

    fn test_store(name: &str) -> (UnlockStore<MemoryKeyStore>, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(format!("{name}.json"));
        (
            UnlockStore::new(
                name.to_owned(),
                Some(uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
                path,
                MemoryKeyStore::default(),
            ),
            temp,
        )
    }

    #[test]
    fn saves_and_loads_unlock_state() {
        let (store, _temp) = test_store("personal");
        let mut vault_keys = BTreeMap::new();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();
        let private_key = UserPrivateKey::from_bytes([7u8; 32]);
        let vault_key = VaultKey::from_bytes([9u8; 32]);
        vault_keys.insert(vault_id, vault_key.clone());

        store
            .save(&UnlockedLocalState::new(
                "personal".to_owned(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
                chrono::Utc::now() + chrono::Duration::minutes(15),
                private_key.clone(),
                vault_keys,
            ))
            .unwrap();

        let loaded = store.load().unwrap().unwrap();

        assert_eq!(loaded.profile, "personal");
        assert_eq!(loaded.private_key.to_base64url(), private_key.to_base64url());
        assert_eq!(
            loaded.vault_keys.get(&vault_id).unwrap().to_base64url(),
            vault_key.to_base64url()
        );
    }

    #[test]
    fn expired_state_is_cleared_and_not_loaded() {
        let (store, _temp) = test_store("personal");
        store
            .save(&UnlockedLocalState::new(
                "personal".to_owned(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
                chrono::Utc::now() - chrono::Duration::minutes(1),
                UserPrivateKey::from_bytes([7u8; 32]),
                BTreeMap::new(),
            ))
            .unwrap();

        assert!(store.load().unwrap().is_none());
        assert!(!store.state_path().exists());
    }

    #[test]
    fn clear_removes_state_file_and_key() {
        let (store, _temp) = test_store("personal");
        store
            .save(&UnlockedLocalState::new(
                "personal".to_owned(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
                chrono::Utc::now() + chrono::Duration::minutes(15),
                UserPrivateKey::from_bytes([7u8; 32]),
                BTreeMap::new(),
            ))
            .unwrap();

        store.clear().unwrap();

        assert!(!store.state_path().exists());
        assert!(store.key_store().get_unlock_key("personal").unwrap().is_none());
    }
}
```

- [ ] **Step 5: Add test dependency**

In `crates/umbra-cli/Cargo.toml`, add:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 6: Run tests to verify they fail**

Run:

```bash
cargo test -p umbra-cli unlock_store
```

Expected: FAIL because `UnlockStore`, `UnlockKeyStore`, and `UnlockedLocalState` do not exist.

- [ ] **Step 7: Implement unlock store**

Replace `crates/umbra-cli/src/unlock_store.rs` with:

```rust
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, LocalUnlockKey, UserPrivateKey, VaultKey,
    decrypt_local_unlock_state, encrypt_local_unlock_state,
};

use crate::cache::profile_cache_dir;
use crate::error::CliError;

const UNLOCK_STATE_VERSION: u16 = 1;
const KEYRING_SERVICE: &str = "umbra";

pub(crate) trait UnlockKeyStore: Clone {
    fn set_unlock_key(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError>;
    fn get_unlock_key(&self, profile: &str) -> Result<Option<LocalUnlockKey>, CliError>;
    fn clear_unlock_key(&self, profile: &str) -> Result<(), CliError>;
}

#[derive(Clone, Debug, Default)]
pub(crate) struct KeyringUnlockKeyStore;

impl UnlockKeyStore for KeyringUnlockKeyStore {
    fn set_unlock_key(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError> {
        keyring::Entry::new(KEYRING_SERVICE, &keyring_account(profile))?
            .set_password(&key.to_base64url())?;
        Ok(())
    }

    fn get_unlock_key(&self, profile: &str) -> Result<Option<LocalUnlockKey>, CliError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_account(profile))?;
        match entry.get_password() {
            Ok(value) => Ok(Some(LocalUnlockKey::from_base64url(&value)?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(CliError::from(error)),
        }
    }

    fn clear_unlock_key(&self, profile: &str) -> Result<(), CliError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_account(profile))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(CliError::from(error)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnlockedLocalState {
    pub(crate) profile: String,
    pub(crate) user_id: uuid::Uuid,
    pub(crate) device_id: uuid::Uuid,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) private_key: UserPrivateKey,
    pub(crate) vault_keys: BTreeMap<uuid::Uuid, VaultKey>,
}

impl UnlockedLocalState {
    pub(crate) fn new(
        profile: String,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        expires_at: DateTime<Utc>,
        private_key: UserPrivateKey,
        vault_keys: BTreeMap<uuid::Uuid, VaultKey>,
    ) -> Self {
        Self {
            profile,
            user_id,
            device_id,
            expires_at,
            private_key,
            vault_keys,
        }
    }

    pub(crate) fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    pub(crate) fn vault_key(&self, vault_id: uuid::Uuid) -> Option<VaultKey> {
        self.vault_keys.get(&vault_id).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredUnlockState {
    version: u16,
    profile: String,
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    expires_at: DateTime<Utc>,
    private_key: String,
    vault_keys: BTreeMap<uuid::Uuid, String>,
}

impl TryFrom<StoredUnlockState> for UnlockedLocalState {
    type Error = CliError;

    fn try_from(value: StoredUnlockState) -> Result<Self, Self::Error> {
        if value.version != UNLOCK_STATE_VERSION {
            return Err(CliError::Input("unsupported unlock state version"));
        }

        let vault_keys = value
            .vault_keys
            .into_iter()
            .map(|(vault_id, key)| Ok((vault_id, VaultKey::from_base64url(&key)?)))
            .collect::<Result<BTreeMap<_, _>, CliError>>()?;

        Ok(Self {
            profile: value.profile,
            user_id: value.user_id,
            device_id: value.device_id,
            expires_at: value.expires_at,
            private_key: UserPrivateKey::from_base64url(&value.private_key)?,
            vault_keys,
        })
    }
}

impl From<&UnlockedLocalState> for StoredUnlockState {
    fn from(value: &UnlockedLocalState) -> Self {
        Self {
            version: UNLOCK_STATE_VERSION,
            profile: value.profile.clone(),
            user_id: value.user_id,
            device_id: value.device_id,
            expires_at: value.expires_at,
            private_key: value.private_key.to_base64url(),
            vault_keys: value
                .vault_keys
                .iter()
                .map(|(vault_id, key)| (*vault_id, key.to_base64url()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UnlockStatus {
    pub(crate) unlocked: bool,
    pub(crate) profile: String,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) vault_count: usize,
}

#[derive(Clone)]
pub(crate) struct UnlockStore<K: UnlockKeyStore = KeyringUnlockKeyStore> {
    profile: String,
    device_id: Option<uuid::Uuid>,
    state_path: PathBuf,
    key_store: K,
}

impl UnlockStore<KeyringUnlockKeyStore> {
    pub(crate) fn open(profile: &str, device_id: Option<uuid::Uuid>) -> Self {
        Self::new(
            profile.to_owned(),
            device_id,
            profile_cache_dir(profile).join("unlock-state.json"),
            KeyringUnlockKeyStore,
        )
    }
}

impl<K: UnlockKeyStore> UnlockStore<K> {
    pub(crate) fn new(
        profile: String,
        device_id: Option<uuid::Uuid>,
        state_path: PathBuf,
        key_store: K,
    ) -> Self {
        Self {
            profile,
            device_id,
            state_path,
            key_store,
        }
    }

    pub(crate) fn save(&self, state: &UnlockedLocalState) -> Result<(), CliError> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let key = LocalUnlockKey::generate();
        let aad = self.aad(state.device_id);
        let plaintext = serde_json::to_vec(&StoredUnlockState::from(state))?;
        let envelope = encrypt_local_unlock_state(&key, aad, &plaintext)?;
        fs::write(&self.state_path, serde_json::to_vec_pretty(&envelope)?)?;
        self.key_store.set_unlock_key(&self.profile, &key)?;
        Ok(())
    }

    pub(crate) fn load(&self) -> Result<Option<UnlockedLocalState>, CliError> {
        if !self.state_path.exists() {
            return Ok(None);
        }

        let Some(key) = self.key_store.get_unlock_key(&self.profile)? else {
            self.remove_state_file()?;
            return Ok(None);
        };

        let envelope: CryptoEnvelopeV1 = serde_json::from_slice(&fs::read(&self.state_path)?)?;
        let device_id = self.device_id.ok_or(CliError::Locked)?;
        let aad = self.aad(device_id);
        let plaintext = decrypt_local_unlock_state(&key, &aad, &envelope)?;
        let state = UnlockedLocalState::try_from(serde_json::from_slice::<StoredUnlockState>(
            &plaintext,
        )?)?;

        if state.is_expired(Utc::now()) {
            self.clear()?;
            return Ok(None);
        }

        Ok(Some(state))
    }

    pub(crate) fn clear(&self) -> Result<(), CliError> {
        self.remove_state_file()?;
        self.key_store.clear_unlock_key(&self.profile)
    }

    pub(crate) fn status(&self) -> Result<UnlockStatus, CliError> {
        let state = self.load()?;
        Ok(UnlockStatus {
            unlocked: state.is_some(),
            profile: self.profile.clone(),
            expires_at: state.as_ref().map(|state| state.expires_at),
            vault_count: state.as_ref().map(|state| state.vault_keys.len()).unwrap_or(0),
        })
    }

    pub(crate) fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub(crate) fn key_store(&self) -> &K {
        &self.key_store
    }

    fn aad(&self, device_id: uuid::Uuid) -> AadV1 {
        AadV1::local_unlock_state(&self.profile, device_id.to_string())
    }

    fn remove_state_file(&self) -> Result<(), CliError> {
        match fs::remove_file(&self.state_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(CliError::from(error)),
        }
    }
}

fn keyring_account(profile: &str) -> String {
    format!("unlock:{profile}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};
    use umbra_crypto::{LocalUnlockKey, UserPrivateKey, VaultKey};

    #[derive(Clone, Default)]
    struct MemoryKeyStore {
        values: Arc<Mutex<HashMap<String, String>>>,
    }

    impl UnlockKeyStore for MemoryKeyStore {
        fn set_unlock_key(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError> {
            self.values
                .lock()
                .unwrap()
                .insert(profile.to_owned(), key.to_base64url());
            Ok(())
        }

        fn get_unlock_key(&self, profile: &str) -> Result<Option<LocalUnlockKey>, CliError> {
            self.values
                .lock()
                .unwrap()
                .get(profile)
                .map(|value| LocalUnlockKey::from_base64url(value).map_err(CliError::from))
                .transpose()
        }

        fn clear_unlock_key(&self, profile: &str) -> Result<(), CliError> {
            self.values.lock().unwrap().remove(profile);
            Ok(())
        }
    }

    fn test_store(name: &str) -> (UnlockStore<MemoryKeyStore>, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(format!("{name}.json"));
        (
            UnlockStore::new(
                name.to_owned(),
                Some(uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
                path,
                MemoryKeyStore::default(),
            ),
            temp,
        )
    }

    #[test]
    fn saves_and_loads_unlock_state() {
        let (store, _temp) = test_store("personal");
        let mut vault_keys = BTreeMap::new();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();
        let private_key = UserPrivateKey::from_bytes([7u8; 32]);
        let vault_key = VaultKey::from_bytes([9u8; 32]);
        vault_keys.insert(vault_id, vault_key.clone());

        store
            .save(&UnlockedLocalState::new(
                "personal".to_owned(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                chrono::Utc::now() + chrono::Duration::minutes(15),
                private_key.clone(),
                vault_keys,
            ))
            .unwrap();

        let loaded = store.load().unwrap().unwrap();

        assert_eq!(loaded.profile, "personal");
        assert_eq!(loaded.private_key.to_base64url(), private_key.to_base64url());
        assert_eq!(
            loaded.vault_keys.get(&vault_id).unwrap().to_base64url(),
            vault_key.to_base64url()
        );
    }

    #[test]
    fn expired_state_is_cleared_and_not_loaded() {
        let (store, _temp) = test_store("personal");
        store
            .save(&UnlockedLocalState::new(
                "personal".to_owned(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                chrono::Utc::now() - chrono::Duration::minutes(1),
                UserPrivateKey::from_bytes([7u8; 32]),
                BTreeMap::new(),
            ))
            .unwrap();

        assert!(store.load().unwrap().is_none());
        assert!(!store.state_path().exists());
    }

    #[test]
    fn clear_removes_state_file_and_key() {
        let (store, _temp) = test_store("personal");
        store
            .save(&UnlockedLocalState::new(
                "personal".to_owned(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                chrono::Utc::now() + chrono::Duration::minutes(15),
                UserPrivateKey::from_bytes([7u8; 32]),
                BTreeMap::new(),
            ))
            .unwrap();

        store.clear().unwrap();

        assert!(!store.state_path().exists());
        assert!(store.key_store().get_unlock_key("personal").unwrap().is_none());
    }
}
```

- [ ] **Step 8: Run unlock store tests**

Run:

```bash
cargo test -p umbra-cli unlock_store
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml crates/umbra-cli/Cargo.toml crates/umbra-cli/src/error.rs crates/umbra-cli/src/main.rs crates/umbra-cli/src/unlock_store.rs
git commit -m "feat(cli): add encrypted unlock store"
```

---

### Task 3: Add Unlock, Lock, And Status Command Shapes

**Files:**
- Modify: `crates/umbra-cli/src/main.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add parser tests**

In `crates/umbra-cli/src/tests.rs`, add:

```rust
#[test]
fn parses_unlock_lock_and_status_commands() {
    let unlock = Cli::parse_from([
        "umbra",
        "unlock",
        "--vault",
        "Personal",
        "--ttl-minutes",
        "30",
    ]);
    assert!(matches!(
        unlock.command,
        Command::Unlock {
            vault: Some(name),
            ttl_minutes: 30,
            all: false,
            ..
        } if name == "Personal"
    ));

    let unlock_all = Cli::parse_from(["umbra", "unlock", "--all"]);
    assert!(matches!(
        unlock_all.command,
        Command::Unlock {
            all: true,
            ttl_minutes: 15,
            ..
        }
    ));

    let lock = Cli::parse_from(["umbra", "lock"]);
    assert!(matches!(lock.command, Command::Lock));

    let status = Cli::parse_from(["umbra", "status"]);
    assert!(matches!(status.command, Command::Status));
}
```

- [ ] **Step 2: Run parser test to verify it fails**

Run:

```bash
cargo test -p umbra-cli parses_unlock_lock_and_status_commands
```

Expected: FAIL because the command variants do not exist.

- [ ] **Step 3: Add command variants**

In `crates/umbra-cli/src/main.rs`, add these variants to `pub enum Command` after `Login`:

```rust
Unlock {
    #[arg(long)]
    vault_id: Option<VaultId>,
    #[arg(long)]
    vault: Option<String>,
    #[arg(long)]
    all: bool,
    #[arg(long, default_value_t = 15)]
    ttl_minutes: i64,
},
Lock,
Status,
```

- [ ] **Step 4: Run parser tests**

Run:

```bash
cargo test -p umbra-cli parses_unlock_lock_and_status_commands
cargo test -p umbra-cli
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbra-cli/src/main.rs crates/umbra-cli/src/tests.rs
git commit -m "feat(cli): add unlock command shapes"
```

---

### Task 4: Implement Unlock, Lock, And Status Commands

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/unlock_store.rs`
- Test: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add helper functions in commands**

In `crates/umbra-cli/src/commands.rs`, add this import at the top:

```rust
use std::collections::BTreeMap;
```

Add this helper after `resolve_vault_id`:

```rust
fn selected_unlock_vaults(
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: Option<VaultId>,
    vault_name: Option<&str>,
    all: bool,
) -> Result<Vec<VaultId>, CliError> {
    if all && (vault_id.is_some() || vault_name.is_some()) {
        return Err(CliError::Input("use either --all or a single vault selector"));
    }

    if all {
        let vaults = cache.cached_vault_ids()?;
        if vaults.is_empty() {
            return Err(CliError::Input("no cached vaults; run `umbra vault list` first"));
        }
        return Ok(vaults);
    }

    Ok(vec![resolve_vault_id(profile, cache, vault_id, vault_name)?])
}
```

- [ ] **Step 2: Add cache method for vault ids**

In `crates/umbra-cli/src/cache.rs`, add this method in `impl LocalCache` near `find_vaults_by_name`:

```rust
pub fn cached_vault_ids(&self) -> Result<Vec<uuid::Uuid>, CliError> {
    let mut statement = self.connection.prepare(
        r#"
        SELECT vault_id
        FROM vaults
        ORDER BY name ASC, vault_id ASC
        "#,
    )?;
    let rows = statement.query_map([], |row| parse_uuid(row.get::<_, String>(0)?))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(CliError::from)
}
```

Add this assertion to `upserts_vault_metadata_and_finds_by_name`:

```rust
assert_eq!(cache.cached_vault_ids().unwrap(), vec![vault_id]);
```

- [ ] **Step 3: Run cache test**

Run:

```bash
cargo test -p umbra-cli upserts_vault_metadata_and_finds_by_name
```

Expected: PASS.

- [ ] **Step 4: Implement command handling**

In `crates/umbra-cli/src/commands.rs`, add these match arms after `Command::Login`:

```rust
Command::Unlock {
    vault_id,
    vault,
    all,
    ttl_minutes,
} => {
    let profile = active_profile(&config)?;
    let user_id = profile.user_id.ok_or(CliError::Input(
        "profile has no user id; run `umbra login` first",
    ))?;
    let device_id = profile.device_id.ok_or(CliError::Input(
        "profile has no device id; run `umbra register` first",
    ))?;
    if ttl_minutes <= 0 {
        return Err(CliError::Input("ttl-minutes must be greater than zero"));
    }

    let mut cache = crate::cache::LocalCache::open(&config.active_profile)?;
    if !all {
        let selected_vault = resolve_vault_id(profile, &cache, vault_id, vault.as_deref())?;
        crate::sync::ensure_vault_synced(
            profile,
            &mut cache,
            selected_vault,
            crate::sync::SyncMode::IfChanged,
        )
        .await?;
    }

    let vault_ids = selected_unlock_vaults(profile, &cache, vault_id, vault.as_deref(), all)?;
    let password = rpassword::prompt_password("Master password: ")?;
    let unlocked = crate::crypto_state::load_unlocked_profile(
        profile,
        &MasterPassword::new(password.into_bytes()),
    )?;
    let mut vault_keys = BTreeMap::new();
    for vault_id in vault_ids {
        let wrapping = cache
            .latest_key_wrapping(vault_id, user_id)?
            .ok_or(CliError::MissingVaultKeyWrapping(vault_id))?;
        let envelope: VaultKeyWrappingEnvelopeV1 = serde_json::from_value(wrapping.envelope)?;
        let aad = AadV1::vault_key_wrapping(vault_id.to_string());
        let vault_key = unwrap_vault_key(&unlocked.private_key, &aad, &envelope)?;
        vault_keys.insert(vault_id, vault_key);
    }

    let state = crate::unlock_store::UnlockedLocalState::new(
        config.active_profile.clone(),
        user_id,
        device_id,
        chrono::Utc::now() + chrono::Duration::minutes(ttl_minutes),
        unlocked.private_key,
        vault_keys,
    );
    crate::unlock_store::UnlockStore::open(&config.active_profile, profile.device_id)
        .save(&state)?;
    print_json(&crate::unlock_store::UnlockStatus {
        unlocked: true,
        profile: config.active_profile,
        expires_at: Some(state.expires_at),
        vault_count: state.vault_keys.len(),
    })
}
Command::Lock => {
    let profile = active_profile(&config)?;
    crate::unlock_store::UnlockStore::open(&config.active_profile, profile.device_id).clear()?;
    println!("locked");
    Ok(())
}
Command::Status => {
    let profile = active_profile(&config)?;
    let status =
        crate::unlock_store::UnlockStore::open(&config.active_profile, profile.device_id)
            .status()?;
    print_json(&status)
}
```

- [ ] **Step 5: Run compile-focused tests**

Run:

```bash
cargo test -p umbra-cli parses_unlock_lock_and_status_commands
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/cache.rs crates/umbra-cli/src/commands.rs crates/umbra-cli/src/unlock_store.rs
git commit -m "feat(cli): implement local unlock commands"
```

---

### Task 5: Use Unlocked Vault Keys Before Prompting

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Test: `crates/umbra-cli/src/unlock_store.rs`

- [ ] **Step 1: Add unlock-store helper test**

In `crates/umbra-cli/src/unlock_store.rs`, add this test:

```rust
#[test]
fn loaded_state_returns_vault_key_by_id() {
    let (store, _temp) = test_store("personal");
    let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();
    let mut vault_keys = BTreeMap::new();
    vault_keys.insert(vault_id, VaultKey::from_bytes([9u8; 32]));

    store
        .save(&UnlockedLocalState::new(
            "personal".to_owned(),
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            chrono::Utc::now() + chrono::Duration::minutes(15),
            UserPrivateKey::from_bytes([7u8; 32]),
            vault_keys,
        ))
        .unwrap();

    let loaded = store.load().unwrap().unwrap();
    assert_eq!(
        loaded.vault_key(vault_id).unwrap().to_base64url(),
        VaultKey::from_bytes([9u8; 32]).to_base64url()
    );
}
```

- [ ] **Step 2: Run helper test**

Run:

```bash
cargo test -p umbra-cli loaded_state_returns_vault_key_by_id
```

Expected: PASS.

- [ ] **Step 3: Rename vault key helper**

In `crates/umbra-cli/src/commands.rs`, rename:

```rust
fn unlock_vault_key_from_cache(
```

to:

```rust
fn unlock_vault_key(
```

Update every call site from:

```rust
unlock_vault_key_from_cache(profile, &cache, vault_id)?
```

to:

```rust
unlock_vault_key(&config.active_profile, profile, &cache, vault_id)?
```

Then change the function signature to:

```rust
fn unlock_vault_key(
    profile_name: &str,
    profile: &crate::config::ProfileConfig,
    cache: &crate::cache::LocalCache,
    vault_id: VaultId,
) -> Result<VaultKey, CliError> {
```

- [ ] **Step 4: Check unlock state before password prompt**

At the start of `unlock_vault_key`, before reading `user_id`, add:

```rust
if let Some(state) =
    crate::unlock_store::UnlockStore::open(profile_name, profile.device_id).load()?
{
    if let Some(vault_key) = state.vault_key(vault_id) {
        return Ok(vault_key);
    }
}
```

Keep the existing master-password fallback below this block.

- [ ] **Step 5: Run CLI tests and clippy**

Run:

```bash
cargo test -p umbra-cli
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/commands.rs crates/umbra-cli/src/unlock_store.rs
git commit -m "feat(cli): reuse unlocked vault keys"
```

---

### Task 6: Remove Unnecessary Password Prompt From Vault Create

**Files:**
- Modify: `crates/umbra-cli/src/commands.rs`
- Modify: `crates/umbra-cli/src/tests.rs`

- [ ] **Step 1: Add helper for profile public key**

In `crates/umbra-cli/src/commands.rs`, add this helper after `require_login`:

```rust
fn profile_public_key(
    profile: &crate::config::ProfileConfig,
) -> Result<umbra_crypto::UserPublicKey, CliError> {
    profile
        .client_public_key
        .as_deref()
        .ok_or(CliError::MissingCryptoMaterial)
        .and_then(|value| umbra_crypto::UserPublicKey::from_base64url(value).map_err(CliError::from))
}
```

- [ ] **Step 2: Change vault create wrapping**

In the `Command::Vault(VaultCommand::Create { ... })` arm, replace:

```rust
None => {
    let password = rpassword::prompt_password("Master password: ")?;
    let unlocked = crate::crypto_state::load_unlocked_profile(
        profile,
        &MasterPassword::new(password.into_bytes()),
    )?;
    let vault_key = generate_vault_key();
    let aad = AadV1::vault_key_wrapping(requested_vault_id.to_string());
    let wrapping = wrap_vault_key_for_user(&unlocked.public_key, &vault_key, aad)?;
    serde_json::to_value(wrapping)?
}
```

with:

```rust
None => {
    let public_key = profile_public_key(profile)?;
    let vault_key = generate_vault_key();
    let aad = AadV1::vault_key_wrapping(requested_vault_id.to_string());
    let wrapping = wrap_vault_key_for_user(&public_key, &vault_key, aad)?;
    serde_json::to_value(wrapping)?
}
```

- [ ] **Step 3: Remove unused import**

If `MasterPassword` is no longer used at the top because all remaining call sites use fully qualified `umbra_crypto::MasterPassword`, remove it from:

```rust
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, MasterPassword, VaultKey, VaultKeyWrappingEnvelopeV1, decrypt_item,
    encrypt_item, generate_vault_key, unwrap_vault_key, wrap_vault_key_for_user,
};
```

The final import should be:

```rust
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, VaultKey, VaultKeyWrappingEnvelopeV1, decrypt_item, encrypt_item,
    generate_vault_key, unwrap_vault_key, wrap_vault_key_for_user,
};
```

- [ ] **Step 4: Update remaining `MasterPassword` calls**

In `commands.rs`, where the code still says:

```rust
&MasterPassword::new(password.into_bytes())
```

change it to:

```rust
&umbra_crypto::MasterPassword::new(password.into_bytes())
```

Do not change the registration code if it already uses `umbra_crypto::MasterPassword::new`.

- [ ] **Step 5: Run focused checks**

Run:

```bash
cargo test -p umbra-cli parses_vault_create_without_wrapping_json
cargo clippy -p umbra-cli --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbra-cli/src/commands.rs
git commit -m "fix(cli): avoid password prompt for vault create"
```

---

### Task 7: Document Local Unlock Flow

**Files:**
- Modify: `README.md`
- Modify: `docs/threat-model.md`

- [ ] **Step 1: Update README happy path**

In `README.md`, in "Current CLI Happy Path", after:

```bash
umbra vault create Personal
```

add:

```bash
umbra unlock --vault Personal --ttl-minutes 30
```

Then add this paragraph after the command block:

```markdown
`umbra unlock` decrypts the account private key once, unwraps selected vault keys from the local encrypted-envelope cache, and writes an encrypted local unlock state. The random key for that unlock state is stored in the OS keychain. `umbra lock` removes both the keychain entry and the encrypted unlock state file.
```

- [ ] **Step 2: Add cache section note**

In `README.md`, under "Local CLI Cache", add:

```markdown
The normal online read/write commands first try the local unlock state. If the selected vault key is not unlocked, the CLI falls back to the master-password prompt and unwraps the vault key from the cached wrapping.
```

- [ ] **Step 3: Update threat model**

In `docs/threat-model.md`, add this section after the existing local cache discussion:

```markdown
## Local Unlock State

The CLI can store a short-lived local unlock state after `umbra unlock`.

The unlock state file contains the user private key and selected vault keys, but it is encrypted with a random local unlock key. That random key is stored in the operating system keychain, scoped to the local Umbra profile.

This protects against a simple copy of the SQLite cache or unlock state file. It does not fully protect against malware running as the same OS user, a compromised OS keychain, a process memory dump while Umbra is unlocked, or an attacker with interactive access to the unlocked account.

`umbra lock` removes the keychain entry and encrypted unlock state file. Expired unlock states are removed on the next status/load attempt.
```

- [ ] **Step 4: Commit docs**

```bash
git add README.md docs/threat-model.md
git commit -m "docs(cli): document local unlock"
```

---

### Task 8: Final Verification And Push

**Files:**
- No code files changed in this task.

- [ ] **Step 1: Run full formatting check**

Run:

```bash
cargo fmt -- --check
```

Expected: PASS.

- [ ] **Step 2: Run full tests**

Run:

```bash
cargo test
```

Expected: PASS.

- [ ] **Step 3: Run full clippy**

Run:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 4: Inspect commits**

Run:

```bash
git status --short --branch
git log --oneline --decorate -10
```

Expected:

```txt
## main...origin/main [ahead N]
```

and the latest commits include:

```txt
docs(cli): document local unlock
fix(cli): avoid password prompt for vault create
feat(cli): reuse unlocked vault keys
feat(cli): implement local unlock commands
feat(cli): add unlock command shapes
feat(cli): add encrypted unlock store
feat(crypto): add local unlock envelopes
```

- [ ] **Step 5: Push**

Run:

```bash
git push origin main
```

Expected: push succeeds.

---

## Self-Review

Spec coverage:

- Reduces repeated master-password prompts: Tasks 4 and 5.
- Adds user-facing `unlock`, `lock`, and `status`: Tasks 3 and 4.
- Keeps local key material encrypted at rest: Tasks 1 and 2.
- Uses OS keychain instead of storing unlock key in SQLite/plaintext: Task 2.
- Preserves current fallback behavior when locked: Task 5.
- Avoids unnecessary password prompt during vault creation: Task 6.
- Documents threat model and UX: Task 7.

Placeholder scan:

- No blocked placeholder markers or unbounded error-handling instructions remain.
- Every code-changing step includes concrete code or concrete replacement instructions.

Type consistency:

- `LocalUnlockKey`, `UnlockedLocalState`, `UnlockStore`, `UnlockStatus`, and `UnlockKeyStore` are introduced before later tasks use them.
- Command variants `Unlock`, `Lock`, and `Status` are introduced before command handling uses them.
- `VaultKey::from_base64url` is introduced in Task 1 before `unlock_store` uses it in Task 2.
