use crate::convert::{
    device_state_to_str, item_kind_to_str, member_state_to_str, str_to_device_state,
    str_to_member_state, str_to_vault_kind, str_to_vault_role, vault_kind_to_str,
    vault_role_to_str,
};
use crate::*;
use serial_test::serial;
use umbra_core::{DeviceState, ItemKind, MemberState, OrgRole, VaultKind, VaultRole};

#[test]
fn enum_string_conversions_roundtrip() {
    assert_eq!(
        str_to_vault_kind(vault_kind_to_str(VaultKind::Shared)).unwrap(),
        VaultKind::Shared
    );
    assert_eq!(
        str_to_vault_role(vault_role_to_str(VaultRole::Editor)).unwrap(),
        VaultRole::Editor
    );
    assert_eq!(
        str_to_member_state(member_state_to_str(MemberState::Active)).unwrap(),
        MemberState::Active
    );
    assert_eq!(
        str_to_device_state(device_state_to_str(DeviceState::Trusted)).unwrap(),
        DeviceState::Trusted
    );
    assert_eq!(item_kind_to_str(&ItemKind::ApiKey), "api_key");
}

#[tokio::test]
async fn sqlite_migrations_create_required_schema() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();

    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let users_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'",
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    let devices_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'devices'",
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    assert_eq!(users_exists, 1);
    assert_eq!(devices_exists, 1);
}

#[tokio::test]
async fn sqlite_users_devices_and_sessions_flow() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let user = create_test_user_on(&storage, "sqlite-user@example.com").await;
    let auth = storage
        .upsert_user_auth(UpsertUserAuth {
            user_id: user.id,
            auth_method: "opaque".to_owned(),
            auth_data: serde_json::json!({"server_setup": "opaque-record"}),
        })
        .await
        .unwrap();
    assert_eq!(auth.user_id, user.id);
    assert_eq!(
        storage.find_user_auth(user.id).await.unwrap().auth_method,
        "opaque"
    );

    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "sqlite laptop".to_owned(),
            public_key: Some("device-public-key".to_owned()),
            fingerprint: "SHA256:sqlite".to_owned(),
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
        })
        .await
        .unwrap();

    let session = storage
        .create_session(CreateSession {
            id: None,
            user_id: user.id,
            device_id: Some(device.id),
            token_hash: "sqlite-token-hash".to_owned(),
            auth_scheme: "signed".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        })
        .await
        .unwrap();

    let loaded_session = storage.find_active_session_by_id(session.id).await.unwrap();
    assert_eq!(loaded_session.device_id, Some(device.id));
    assert_eq!(loaded_session.auth_scheme, "signed");

    storage
        .remember_session_nonce(session.id, "nonce-1")
        .await
        .unwrap();
    assert!(matches!(
        storage.remember_session_nonce(session.id, "nonce-1").await,
        Err(StorageError::Conflict)
    ));
}

#[tokio::test]
async fn sqlite_vault_item_and_rotation_flow() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let user = create_test_user_on(&storage, "sqlite-vault@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "SQLite Personal".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({"min_envelope_version": 1}),
        })
        .await
        .unwrap();

    storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id: user.id,
            role: VaultRole::Owner,
            state: MemberState::Active,
        })
        .await
        .unwrap();

    let revision = storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id: vault.id,
            kind: ItemKind::Login,
            author_user_id: Some(user.id),
            envelope: serde_json::json!({"ciphertext": "encrypted"}),
        })
        .await
        .unwrap();

    assert_eq!(revision.revision, 1);
    assert_eq!(
        storage
            .list_item_revisions_since(vault.id, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        storage
            .has_active_vault_membership(vault.id, user.id)
            .await
            .unwrap()
    );
}

#[tokio::test]
#[serial(postgres)]
async fn postgres_migrations_create_required_schema() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };

    let tables: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN ('users', 'orgs', 'vaults', 'vault_members', 'vault_key_wrappings', 'item_revisions', 'sessions', 'session_nonces', 'device_recovery_challenges')
        "#,
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    assert_eq!(tables, 9);
}

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
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
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

    storage
        .remember_session_nonce(session.id, "nonce-1")
        .await
        .unwrap();
    assert!(matches!(
        storage.remember_session_nonce(session.id, "nonce-1").await,
        Err(StorageError::Conflict)
    ));
}

#[tokio::test]
#[serial(postgres)]
async fn postgres_revoke_sessions_for_device_revokes_active_session() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let user = create_test_user(&storage, "revoke-session@example.com").await;
    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "session laptop".to_owned(),
            public_key: Some("device-public-key".to_owned()),
            fingerprint: "session-device".to_owned(),
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
        })
        .await
        .unwrap();
    let session = storage
        .create_session(CreateSession {
            id: None,
            user_id: user.id,
            device_id: Some(device.id),
            token_hash: "revoke-token-hash".to_owned(),
            auth_scheme: "signed".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
        })
        .await
        .unwrap();

    let rows = storage.revoke_sessions_for_device(device.id).await.unwrap();
    assert_eq!(rows, 1);
    assert!(matches!(
        storage.find_active_session_by_id(session.id).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        storage
            .find_active_session_by_hash("revoke-token-hash")
            .await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
#[serial(postgres)]
async fn postgres_devices_support_pending_trust_and_revoke() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let user = create_test_user(&storage, "pending-device@example.com").await;
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    let pending = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "new laptop".to_owned(),
            public_key: Some("device-public-key".to_owned()),
            fingerprint: "device-fingerprint".to_owned(),
            state: DeviceState::Pending,
            approval_code_hash: Some("approval-hash".to_owned()),
            approval_expires_at: Some(expires_at),
            bootstrap_public_key: Some("bootstrap-public-key".to_owned()),
        })
        .await
        .unwrap();

    assert_eq!(pending.state, DeviceState::Pending);
    assert_eq!(pending.approval_code_hash.as_deref(), Some("approval-hash"));
    assert_eq!(
        pending.bootstrap_public_key.as_deref(),
        Some("bootstrap-public-key")
    );
    assert_eq!(pending.bootstrap_bundle, None);
    assert_eq!(pending.trusted_at, None);

    let pending_devices = storage
        .list_pending_devices_for_user(user.id)
        .await
        .unwrap();
    assert_eq!(pending_devices.len(), 1);
    assert_eq!(pending_devices[0].id, pending.id);

    let found = storage
        .find_pending_device_by_approval_hash(user.id, "approval-hash")
        .await
        .unwrap();
    assert_eq!(found.id, pending.id);

    let bundle = serde_json::json!({"ciphertext": "opaque-bootstrap-bundle"});
    let approved = storage
        .approve_pending_device(ApprovePendingDevice {
            device_id: pending.id,
            bootstrap_bundle: bundle.clone(),
        })
        .await
        .unwrap();

    assert_eq!(approved.state, DeviceState::Trusted);
    assert_eq!(approved.approval_code_hash, None);
    assert_eq!(approved.approval_expires_at, None);
    assert_eq!(approved.bootstrap_bundle, Some(bundle));
    assert!(approved.trusted_at.is_some());

    storage.revoke_device(approved.id).await.unwrap();
    let revoked = storage.find_device_by_id(approved.id).await.unwrap();
    assert_eq!(revoked.state, DeviceState::Revoked);
    assert!(revoked.revoked_at.is_some());
}

#[tokio::test]
#[serial(postgres)]
async fn postgres_recovery_challenge_consumes_once() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let user = create_test_user(&storage, "recovery-device@example.com").await;
    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "recovering laptop".to_owned(),
            public_key: Some("device-public-key".to_owned()),
            fingerprint: "recovery-device".to_owned(),
            state: DeviceState::Pending,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: Some("bootstrap-public-key".to_owned()),
        })
        .await
        .unwrap();
    let challenge = storage
        .create_recovery_challenge(CreateRecoveryChallenge {
            id: None,
            user_id: user.id,
            device_id: device.id,
            challenge_hash: "challenge-hash".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        })
        .await
        .unwrap();

    let consumed = storage
        .consume_recovery_challenge(challenge.id, user.id, device.id, "challenge-hash")
        .await
        .unwrap();
    assert!(consumed.consumed_at.is_some());

    assert!(matches!(
        storage
            .consume_recovery_challenge(challenge.id, user.id, device.id, "challenge-hash")
            .await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
#[serial(postgres)]
async fn postgres_vault_access_and_rotation_flow() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };
    let owner = create_test_user(&storage, "owner@example.com").await;
    let member = create_test_user(&storage, "member@example.com").await;

    let org = storage
        .create_org(CreateOrg {
            id: None,
            name: "Umbra Team".to_owned(),
            created_by: Some(owner.id),
        })
        .await
        .unwrap();
    storage
        .upsert_org_member(UpsertOrgMember {
            org_id: org.id,
            user_id: owner.id,
            role: OrgRole::Owner,
            state: MemberState::Active,
        })
        .await
        .unwrap();
    storage
        .upsert_org_member(UpsertOrgMember {
            org_id: org.id,
            user_id: member.id,
            role: OrgRole::Member,
            state: MemberState::Active,
        })
        .await
        .unwrap();

    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: Some(org.id),
            name: "Platform".to_owned(),
            kind: VaultKind::Shared,
            created_by: Some(owner.id),
            crypto_policy: serde_json::json!({}),
        })
        .await
        .unwrap();
    assert_eq!(vault.access_revision, 0);

    storage
        .create_vault_key_wrapping(CreateVaultKeyWrapping {
            id: None,
            vault_id: vault.id,
            user_id: owner.id,
            device_id: None,
            wrapping_type: "user_public_key".to_owned(),
            envelope: serde_json::json!({"owner": true}),
            key_generation: 1,
        })
        .await
        .unwrap();
    let after_initial_owner_wrapping = storage.find_vault_by_id(vault.id).await.unwrap();
    assert_eq!(after_initial_owner_wrapping.access_revision, 1);

    storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id: owner.id,
            role: VaultRole::Owner,
            state: MemberState::Active,
        })
        .await
        .unwrap();

    assert!(
        !storage
            .has_active_vault_membership(vault.id, member.id)
            .await
            .unwrap()
    );

    storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id: member.id,
            role: VaultRole::Viewer,
            state: MemberState::Active,
        })
        .await
        .unwrap();
    let after_member_access_change = storage.find_vault_by_id(vault.id).await.unwrap();
    assert!(
        after_member_access_change.access_revision > after_initial_owner_wrapping.access_revision
    );

    let member_wrapping = storage
        .create_vault_key_wrapping(CreateVaultKeyWrapping {
            id: None,
            vault_id: vault.id,
            user_id: member.id,
            device_id: None,
            wrapping_type: "user_public_key".to_owned(),
            envelope: serde_json::json!({"member": true}),
            key_generation: 1,
        })
        .await
        .unwrap();

    assert_eq!(member_wrapping.key_generation, 1);
    assert!(
        storage
            .has_active_vault_membership(vault.id, member.id)
            .await
            .unwrap()
    );

    let item_revision = storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id: vault.id,
            kind: ItemKind::ApiKey,
            author_user_id: Some(owner.id),
            envelope: serde_json::json!({"ciphertext": "v1"}),
        })
        .await
        .unwrap();

    storage
        .remove_vault_member(vault.id, member.id)
        .await
        .unwrap();
    let status = storage.rotation_status(vault.id).await.unwrap();
    assert!(status.needs_key_rotation);
    assert!(
        !storage
            .has_active_vault_membership(vault.id, member.id)
            .await
            .unwrap()
    );
    assert!(
        storage
            .list_key_wrappings_for_user_vault(member.id, vault.id)
            .await
            .unwrap()
            .is_empty()
    );

    let rotated = storage
        .finish_vault_key_rotation(FinishVaultKeyRotation {
            vault_id: vault.id,
            author_user_id: Some(owner.id),
            from_generation: 1,
            to_generation: 2,
            new_wrappings: vec![CreateVaultKeyWrapping {
                id: None,
                vault_id: vault.id,
                user_id: owner.id,
                device_id: None,
                wrapping_type: "user_public_key".to_owned(),
                envelope: serde_json::json!({"owner": "rotated"}),
                key_generation: 2,
            }],
            reencrypted_revisions: vec![RotationItemRevisionInput {
                revision_id: None,
                item_id: item_revision.item_id,
                expected_revision: 1,
                envelope: serde_json::json!({"ciphertext": "v2"}),
            }],
        })
        .await
        .unwrap();

    assert_eq!(rotated.current_key_generation, 2);
    assert!(!rotated.needs_key_rotation);
    let sync_status = storage.vault_sync_status(vault.id, owner.id).await.unwrap();
    let latest_vault = storage.find_vault_by_id(vault.id).await.unwrap();
    assert_eq!(sync_status.vault_id, vault.id);
    assert_eq!(
        sync_status.latest_vault_revision,
        latest_vault.vault_revision
    );
    assert_eq!(
        sync_status.latest_access_revision,
        latest_vault.access_revision
    );
    assert_eq!(sync_status.current_key_generation, 2);
    assert!(!sync_status.needs_key_rotation);

    let owner_wrappings = storage
        .list_key_wrappings_for_user_vault(owner.id, vault.id)
        .await
        .unwrap();
    assert_eq!(owner_wrappings.len(), 1);
    assert_eq!(owner_wrappings[0].key_generation, 2);
    let revisions = storage
        .list_item_revisions_since(vault.id, 0)
        .await
        .unwrap();
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[1].key_generation, 2);

    let later_revisions = storage
        .list_item_revisions_since(vault.id, 1)
        .await
        .unwrap();
    assert_eq!(later_revisions.len(), 1);
    assert_eq!(later_revisions[0].revision, 2);
    assert_eq!(
        later_revisions[0].envelope,
        serde_json::json!({"ciphertext": "v2"})
    );

    let current_wrappings = storage
        .list_key_wrappings_for_user_vault(owner.id, vault.id)
        .await
        .unwrap();
    assert_eq!(current_wrappings.len(), 1);
    assert_eq!(current_wrappings[0].key_generation, 2);
    assert_eq!(current_wrappings[0].revoked_at, None);
}

async fn fresh_test_storage() -> Option<Storage> {
    let Ok(database_url) = std::env::var("UMBRA_TEST_DATABASE_URL") else {
        eprintln!("skipping postgres test: UMBRA_TEST_DATABASE_URL is not set");
        return None;
    };
    let storage = Storage::connect(&database_url, 10).await.unwrap();

    sqlx::query("DROP SCHEMA public CASCADE")
        .execute(storage.pool())
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA public")
        .execute(storage.pool())
        .await
        .unwrap();
    umbra_migrations::run(storage.pool()).await.unwrap();

    Some(storage)
}

async fn create_test_user(storage: &Storage, email: &str) -> UserRecord {
    create_test_user_on(storage, email).await
}

async fn create_test_user_on<S: StorageBackend + ?Sized>(storage: &S, email: &str) -> UserRecord {
    storage
        .create_user(CreateUser {
            id: None,
            email: email.to_owned(),
            display_name: Some(email.to_owned()),
            public_key: format!("{email}-public-key"),
            encrypted_private_key: serde_json::json!({"encrypted": true}),
        })
        .await
        .unwrap()
}
