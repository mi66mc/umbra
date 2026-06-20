#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use umbra_crypto::{
    AadV1, CryptoEnvelopeV1, LocalUnlockKey, UserPrivateKey, VaultKey, decrypt_local_unlock_state,
    encrypt_local_unlock_state,
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
    #[cfg(test)]
    fail_promote: bool,
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
            #[cfg(test)]
            fail_promote: false,
        }
    }

    pub(crate) fn save(&self, state: &UnlockedLocalState) -> Result<(), CliError> {
        self.validate_state_identity(state)?;

        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let key = LocalUnlockKey::generate();
        let aad = self.aad(state.device_id);
        let plaintext = serde_json::to_vec(&StoredUnlockState::from(state))?;
        let envelope = encrypt_local_unlock_state(&key, aad, &plaintext)?;
        let temp_path = self.temp_state_path();
        fs::write(&temp_path, serde_json::to_vec_pretty(&envelope)?)?;
        let previous_key = self.key_store.get_unlock_key(&self.profile)?;

        if let Err(error) = self.key_store.set_unlock_key(&self.profile, &key) {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        if let Err(error) = self.promote_temp_file(&temp_path) {
            let _ = fs::remove_file(&temp_path);
            self.restore_unlock_key(previous_key)?;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn load(&self) -> Result<Option<UnlockedLocalState>, CliError> {
        let bytes = match fs::read(&self.state_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.key_store.clear_unlock_key(&self.profile)?;
                return Ok(None);
            }
            Err(error) => return Err(CliError::from(error)),
        };

        let Some(key) = self.key_store.get_unlock_key(&self.profile)? else {
            self.remove_state_file()?;
            return Ok(None);
        };

        let envelope: CryptoEnvelopeV1 = match serde_json::from_slice(&bytes) {
            Ok(envelope) => envelope,
            Err(_) => return self.clear_invalid_state(),
        };
        let Some(device_id) = self.device_id else {
            self.clear()?;
            return Ok(None);
        };
        let aad = self.aad(device_id);
        let plaintext = match decrypt_local_unlock_state(&key, &aad, &envelope) {
            Ok(plaintext) => plaintext,
            Err(_) => return self.clear_invalid_state(),
        };
        let stored: StoredUnlockState = match serde_json::from_slice(&plaintext) {
            Ok(stored) => stored,
            Err(_) => return self.clear_invalid_state(),
        };
        let state = match UnlockedLocalState::try_from(stored) {
            Ok(state) => state,
            Err(_) => return self.clear_invalid_state(),
        };

        if !self.state_matches_store(&state) {
            return self.clear_invalid_state();
        }

        if state.is_expired(Utc::now()) {
            self.clear()?;
            return Ok(None);
        }

        Ok(Some(state))
    }

    pub(crate) fn clear(&self) -> Result<(), CliError> {
        self.remove_state_file()?;
        self.key_store.clear_unlock_key(&self.profile)?;
        Ok(())
    }

    pub(crate) fn status(&self) -> Result<UnlockStatus, CliError> {
        let Some(state) = self.load()? else {
            return Ok(UnlockStatus {
                unlocked: false,
                profile: self.profile.clone(),
                expires_at: None,
                vault_count: 0,
            });
        };

        Ok(UnlockStatus {
            unlocked: true,
            profile: self.profile.clone(),
            expires_at: Some(state.expires_at),
            vault_count: state.vault_keys.len(),
        })
    }

    #[cfg(test)]
    fn state_path(&self) -> &std::path::Path {
        &self.state_path
    }

    #[cfg(test)]
    fn key_store(&self) -> &K {
        &self.key_store
    }

    #[cfg(test)]
    fn with_promote_failure(mut self) -> Self {
        self.fail_promote = true;
        self
    }

    fn aad(&self, device_id: uuid::Uuid) -> AadV1 {
        AadV1::local_unlock_state(&self.profile, device_id.to_string())
    }

    fn validate_state_identity(&self, state: &UnlockedLocalState) -> Result<(), CliError> {
        if !self.state_matches_store(state) {
            return Err(CliError::Input(
                "unlock state does not match active profile/device",
            ));
        }
        Ok(())
    }

    fn state_matches_store(&self, state: &UnlockedLocalState) -> bool {
        state.profile == self.profile && self.device_id == Some(state.device_id)
    }

    fn temp_state_path(&self) -> PathBuf {
        let file_name = self
            .state_path
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("unlock-state.json");
        self.state_path
            .with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()))
    }

    fn restore_unlock_key(&self, previous_key: Option<LocalUnlockKey>) -> Result<(), CliError> {
        if let Some(previous_key) = previous_key {
            self.key_store.set_unlock_key(&self.profile, &previous_key)
        } else {
            self.key_store.clear_unlock_key(&self.profile)
        }
    }

    fn promote_temp_file(&self, temp_path: &std::path::Path) -> Result<(), CliError> {
        #[cfg(test)]
        if self.fail_promote {
            return Err(CliError::from(std::io::Error::other(
                "simulated unlock state promotion failure",
            )));
        }

        promote_temp_file(temp_path, &self.state_path)
    }

    fn clear_invalid_state(&self) -> Result<Option<UnlockedLocalState>, CliError> {
        self.clear()?;
        Ok(None)
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
    format!("unlock:v1:{}", sanitize_keyring_component(profile))
}

fn sanitize_keyring_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(not(windows))]
fn promote_temp_file(
    temp_path: &std::path::Path,
    state_path: &std::path::Path,
) -> Result<(), CliError> {
    fs::rename(temp_path, state_path).map_err(CliError::from)
}

#[cfg(windows)]
fn promote_temp_file(
    temp_path: &std::path::Path,
    state_path: &std::path::Path,
) -> Result<(), CliError> {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    unsafe extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    let temp_path = wide_path(temp_path);
    let state_path = wide_path(state_path);
    // SAFETY: Both path buffers are null-terminated UTF-16 pointers that remain
    // alive for the duration of the call, and the flags request an atomic replace.
    let result = unsafe {
        MoveFileExW(
            temp_path.as_ptr(),
            state_path.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(CliError::from(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().chain(Some(0)).collect()
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
        fail_set: Arc<Mutex<bool>>,
    }

    impl UnlockKeyStore for MemoryKeyStore {
        fn set_unlock_key(&self, profile: &str, key: &LocalUnlockKey) -> Result<(), CliError> {
            if *self.fail_set.lock().unwrap() {
                return Err(CliError::Input("keychain unavailable"));
            }

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

    impl MemoryKeyStore {
        fn fail_set(&self) {
            *self.fail_set.lock().unwrap() = true;
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

    fn unlocked_state(profile: &str, device_id: uuid::Uuid, key_byte: u8) -> UnlockedLocalState {
        let mut vault_keys = BTreeMap::new();
        vault_keys.insert(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap(),
            VaultKey::from_bytes([key_byte; 32]),
        );

        UnlockedLocalState::new(
            profile.to_owned(),
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            device_id,
            chrono::Utc::now() + chrono::Duration::minutes(15),
            UserPrivateKey::from_bytes([7u8; 32]),
            vault_keys,
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
        assert_eq!(
            loaded.private_key.to_base64url(),
            private_key.to_base64url()
        );
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
        assert!(
            store
                .key_store()
                .get_unlock_key("personal")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn keychain_set_failure_does_not_replace_existing_state() {
        let (store, _temp) = test_store("personal");
        let device_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();
        store
            .save(&unlocked_state("personal", device_id, 9))
            .unwrap();
        let before = fs::read(store.state_path()).unwrap();

        store.key_store().fail_set();
        assert!(
            store
                .save(&unlocked_state("personal", device_id, 8))
                .is_err()
        );

        assert_eq!(fs::read(store.state_path()).unwrap(), before);
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(
            loaded.vault_keys.get(&vault_id).unwrap().to_base64url(),
            VaultKey::from_bytes([9u8; 32]).to_base64url()
        );
    }

    #[test]
    fn promotion_failure_restores_previous_key_and_keeps_existing_state() {
        let (store, _temp) = test_store("personal");
        let device_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let vault_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();
        store
            .save(&unlocked_state("personal", device_id, 9))
            .unwrap();
        let before = fs::read(store.state_path()).unwrap();

        let failing_store = store.clone().with_promote_failure();
        assert!(
            failing_store
                .save(&unlocked_state("personal", device_id, 8))
                .is_err()
        );

        assert_eq!(fs::read(store.state_path()).unwrap(), before);
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(
            loaded.vault_keys.get(&vault_id).unwrap().to_base64url(),
            VaultKey::from_bytes([9u8; 32]).to_base64url()
        );
    }

    #[test]
    fn missing_state_file_clears_stale_key() {
        let (store, _temp) = test_store("personal");
        let key = LocalUnlockKey::generate();
        store.key_store().set_unlock_key("personal", &key).unwrap();

        assert!(store.load().unwrap().is_none());
        assert!(
            store
                .key_store()
                .get_unlock_key("personal")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn corrupt_state_is_cleared_and_not_loaded() {
        let (store, _temp) = test_store("personal");
        let device_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        store
            .save(&unlocked_state("personal", device_id, 9))
            .unwrap();
        fs::write(store.state_path(), b"{not json").unwrap();

        assert!(store.load().unwrap().is_none());
        assert!(!store.state_path().exists());
        assert!(
            store
                .key_store()
                .get_unlock_key("personal")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn save_rejects_mismatched_state() {
        let (store, _temp) = test_store("personal");
        let device_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        let error = store
            .save(&unlocked_state("work", device_id, 9))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "input error: unlock state does not match active profile/device"
        );
        assert!(!store.state_path().exists());

        let wrong_device_id =
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let error = store
            .save(&unlocked_state("personal", wrong_device_id, 9))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "input error: unlock state does not match active profile/device"
        );
        assert!(!store.state_path().exists());
    }

    #[test]
    fn loaded_mismatched_state_is_cleared_and_not_loaded() {
        let (store, _temp) = test_store("personal");
        let device_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let key = LocalUnlockKey::generate();
        let stored = StoredUnlockState {
            version: UNLOCK_STATE_VERSION,
            profile: "work".to_owned(),
            user_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            device_id,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(15),
            private_key: UserPrivateKey::from_bytes([7u8; 32]).to_base64url(),
            vault_keys: BTreeMap::new(),
        };
        let envelope = encrypt_local_unlock_state(
            &key,
            store.aad(device_id),
            &serde_json::to_vec(&stored).unwrap(),
        )
        .unwrap();
        fs::write(store.state_path(), serde_json::to_vec(&envelope).unwrap()).unwrap();
        store.key_store().set_unlock_key("personal", &key).unwrap();

        assert!(store.load().unwrap().is_none());
        assert!(!store.state_path().exists());
        assert!(
            store
                .key_store()
                .get_unlock_key("personal")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn keyring_account_includes_versioned_sanitized_profile() {
        assert_eq!(
            keyring_account("miguel@example.com/local"),
            "unlock:v1:miguel_example.com_local"
        );
    }
}
