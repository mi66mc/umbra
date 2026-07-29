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
async fn sqlite_sync_checkpoint_persistence_is_opaque_idempotent_and_ordered() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('sync_checkpoints')")
            .fetch_all(storage.pool())
            .await
            .unwrap();
    assert!(columns.contains(&"state_commitment".to_owned()));
    assert!(columns.contains(&"checkpoint_hash".to_owned()));
    assert!(columns.contains(&"signature".to_owned()));
    assert!(!columns.iter().any(|column| column.contains("envelope")));
    assert!(!columns.iter().any(|column| column.contains("plaintext")));

    sync_checkpoint_persistence_on(&storage).await;
}

#[tokio::test]
async fn sqlite_concurrent_duplicate_sync_checkpoints_are_idempotent() {
    let database_url = format!(
        "sqlite:file:checkpoint-concurrent-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );
    let storage = crate::sqlite::SqliteStorage::connect(&database_url, 2)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    let user = create_test_user_on(&storage, "checkpoint-concurrent@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Concurrent Checkpoint Vault".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({}),
        })
        .await
        .unwrap();
    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "concurrent checkpoint device".to_owned(),
            public_key: Some("concurrent-device-public-key".to_owned()),
            encryption_public_key: None,
            fingerprint: "SHA256:checkpoint-concurrent".to_owned(),
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
        })
        .await
        .unwrap();
    let checkpoint = CreateSyncCheckpoint {
        vault_id: vault.id,
        vault_revision: 1,
        state_commitment: "state-commitment-concurrent".to_owned(),
        checkpoint_hash: "checkpoint-hash-concurrent".to_owned(),
        previous_checkpoint_hash: None,
        author_device_id: device.id,
        signature: "signature-concurrent".to_owned(),
    };

    let first_storage = storage.clone();
    let second_storage = storage.clone();
    let first_checkpoint = checkpoint.clone();
    let (first, second) = tokio::join!(
        async move { first_storage.append_sync_checkpoint(first_checkpoint).await },
        async move { second_storage.append_sync_checkpoint(checkpoint).await },
    );

    assert!(first.is_ok(), "first concurrent append failed: {first:?}");
    assert!(
        second.is_ok(),
        "second concurrent append failed: {second:?}"
    );
}

#[tokio::test]
#[serial(postgres)]
async fn postgres_sync_checkpoint_persistence_is_opaque_idempotent_and_ordered() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };

    sync_checkpoint_persistence_on(&storage).await;
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
            encryption_public_key: None,
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
async fn sqlite_revoking_device_marks_users_active_vaults_for_rotation() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();
    let user = create_test_user_on(&storage, "sqlite-device-revoke@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Rotate after revoke".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({}),
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
    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "revoked laptop".to_owned(),
            public_key: Some("device-public-key".to_owned()),
            encryption_public_key: Some("encryption-public-key".to_owned()),
            fingerprint: "sqlite-revoked-device".to_owned(),
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
        })
        .await
        .unwrap();

    storage.revoke_device(device.id).await.unwrap();

    assert!(
        storage
            .rotation_status(vault.id)
            .await
            .unwrap()
            .needs_key_rotation
    );
}

#[tokio::test]
async fn sqlite_item_deletion_flow() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    item_deletion_flow_on(&storage).await;
}

#[tokio::test]
async fn sqlite_remote_conflict_resolution_advances_vault_revision() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();
    let user = create_test_user_on(&storage, "conflict-owner@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Conflicts".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({}),
        })
        .await
        .unwrap();
    let created = storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id: vault.id,
            kind: ItemKind::Login,
            author_user_id: Some(user.id),
            envelope: serde_json::json!({"ciphertext":"v1"}),
        })
        .await
        .unwrap();
    let current = storage
        .create_item_revision(CreateItemRevision {
            revision_id: None,
            item_id: created.item_id,
            vault_id: vault.id,
            expected_revision: 1,
            author_user_id: Some(user.id),
            envelope: serde_json::json!({"ciphertext":"v2"}),
        })
        .await
        .unwrap();
    let first = storage
        .create_item_conflict(CreateItemConflict {
            id: None,
            vault_id: vault.id,
            item_id: created.item_id,
            base_revision: 1,
            candidate_kind: "update".to_owned(),
            candidate_envelope: Some(serde_json::json!({"ciphertext":"offline-a"})),
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();
    storage
        .create_item_conflict(CreateItemConflict {
            id: None,
            vault_id: vault.id,
            item_id: created.item_id,
            base_revision: 1,
            candidate_kind: "update".to_owned(),
            candidate_envelope: Some(serde_json::json!({"ciphertext":"offline-b"})),
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();
    assert_eq!(
        storage
            .list_open_item_conflicts(vault.id)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(matches!(
        storage
            .create_item_revision(CreateItemRevision {
                revision_id: None,
                item_id: created.item_id,
                vault_id: vault.id,
                expected_revision: current.revision,
                author_user_id: Some(user.id),
                envelope: serde_json::json!({"ciphertext":"blocked"}),
            })
            .await,
        Err(StorageError::Conflict)
    ));
    let vault_revision_before_resolution = storage
        .find_vault_by_id(vault.id)
        .await
        .unwrap()
        .vault_revision;
    let resolved = storage
        .resolve_item_conflict(ResolveItemConflict {
            vault_id: vault.id,
            conflict_id: first.id,
            expected_current_revision: current.revision,
            resolution: "remote".to_owned(),
            envelope: None,
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();
    assert_eq!(resolved.conflict.state, "resolved");
    assert!(resolved.revision.is_none());
    assert!(
        storage
            .list_open_item_conflicts(vault.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .find_vault_by_id(vault.id)
            .await
            .unwrap()
            .vault_revision
            > vault_revision_before_resolution
    );
}

#[tokio::test]
async fn sqlite_local_update_conflict_resolution_creates_candidate_revision_and_closes_candidates()
{
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();
    let user = create_test_user_on(&storage, "conflict-local-update@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Local update conflicts".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({}),
        })
        .await
        .unwrap();
    let created = storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id: vault.id,
            kind: ItemKind::Login,
            author_user_id: Some(user.id),
            envelope: serde_json::json!({"ciphertext":"v1"}),
        })
        .await
        .unwrap();
    let current = storage
        .create_item_revision(CreateItemRevision {
            revision_id: None,
            item_id: created.item_id,
            vault_id: vault.id,
            expected_revision: created.revision,
            author_user_id: Some(user.id),
            envelope: serde_json::json!({"ciphertext":"v2"}),
        })
        .await
        .unwrap();
    let candidate_envelope = serde_json::json!({"ciphertext":"candidate"});
    let selected = storage
        .create_item_conflict(CreateItemConflict {
            id: None,
            vault_id: vault.id,
            item_id: created.item_id,
            base_revision: created.revision,
            candidate_kind: "update".to_owned(),
            candidate_envelope: Some(candidate_envelope.clone()),
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();
    storage
        .create_item_conflict(CreateItemConflict {
            id: None,
            vault_id: vault.id,
            item_id: created.item_id,
            base_revision: created.revision,
            candidate_kind: "update".to_owned(),
            candidate_envelope: Some(serde_json::json!({"ciphertext":"discarded"})),
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();

    let resolved = storage
        .resolve_item_conflict(ResolveItemConflict {
            vault_id: vault.id,
            conflict_id: selected.id,
            expected_current_revision: current.revision,
            resolution: "local".to_owned(),
            envelope: Some(candidate_envelope.clone()),
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();

    let revision = resolved.revision.unwrap();
    assert_eq!(revision.revision, current.revision + 1);
    assert_eq!(revision.envelope, candidate_envelope);
    assert!(
        storage
            .list_open_item_conflicts(vault.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn sqlite_local_delete_conflict_resolution_returns_deleted_item_for_sync() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();
    let user = create_test_user_on(&storage, "conflict-local-delete@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Local delete conflicts".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({}),
        })
        .await
        .unwrap();
    let created = storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id: vault.id,
            kind: ItemKind::Login,
            author_user_id: Some(user.id),
            envelope: serde_json::json!({"ciphertext":"v1"}),
        })
        .await
        .unwrap();
    let selected = storage
        .create_item_conflict(CreateItemConflict {
            id: None,
            vault_id: vault.id,
            item_id: created.item_id,
            base_revision: created.revision,
            candidate_kind: "delete".to_owned(),
            candidate_envelope: None,
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();

    let resolved = storage
        .resolve_item_conflict(ResolveItemConflict {
            vault_id: vault.id,
            conflict_id: selected.id,
            expected_current_revision: created.revision,
            resolution: "local".to_owned(),
            envelope: None,
            author_user_id: Some(user.id),
        })
        .await
        .unwrap();

    let deleted = resolved.deleted.unwrap();
    assert_eq!(deleted.item_id, created.item_id);
    assert_eq!(deleted.vault_id, vault.id);
    assert!(
        storage
            .list_deleted_item_ids_since(vault.id, created.vault_revision)
            .await
            .unwrap()
            .iter()
            .any(|record| record.item_id == created.item_id)
    );
}

#[tokio::test]
async fn sqlite_vault_invite_lifecycle() {
    let storage = crate::sqlite::SqliteStorage::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    umbra_migrations::run_sqlite(storage.pool()).await.unwrap();

    vault_invite_lifecycle_on(&storage).await;
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
async fn postgres_item_deletion_flow() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };

    item_deletion_flow_on(&storage).await;
}

#[tokio::test]
#[serial(postgres)]
async fn postgres_vault_invite_lifecycle() {
    let Some(storage) = fresh_test_storage().await else {
        return;
    };

    vault_invite_lifecycle_on(&storage).await;
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
            encryption_public_key: None,
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
            encryption_public_key: None,
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
            encryption_public_key: None,
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

    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Postgres revoke rotation".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({}),
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

    storage.revoke_device(approved.id).await.unwrap();
    let revoked = storage.find_device_by_id(approved.id).await.unwrap();
    assert_eq!(revoked.state, DeviceState::Revoked);
    assert!(revoked.revoked_at.is_some());
    assert!(
        storage
            .rotation_status(vault.id)
            .await
            .unwrap()
            .needs_key_rotation
    );
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
            encryption_public_key: None,
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

async fn item_deletion_flow_on<S: StorageBackend + ?Sized>(storage: &S) {
    let owner = create_test_user_on(storage, "delete-owner@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Delete Vault".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(owner.id),
            crypto_policy: serde_json::json!({"min_envelope_version": 1}),
        })
        .await
        .unwrap();
    storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id: owner.id,
            role: VaultRole::Owner,
            state: MemberState::Active,
        })
        .await
        .unwrap();

    let created = storage
        .create_encrypted_item(CreateEncryptedItem {
            item_id: None,
            revision_id: None,
            vault_id: vault.id,
            kind: ItemKind::Login,
            author_user_id: Some(owner.id),
            envelope: serde_json::json!({"ciphertext": "v1"}),
        })
        .await
        .unwrap();

    let deleted = storage
        .delete_item(DeleteItem {
            item_id: created.item_id,
            vault_id: vault.id,
            expected_revision: created.revision,
            author_user_id: Some(owner.id),
        })
        .await
        .unwrap();

    assert_eq!(deleted.item_id, created.item_id);
    assert_eq!(deleted.vault_id, vault.id);
    assert!(deleted.deleted_vault_revision > created.vault_revision);

    let deleted_since_create = storage
        .list_deleted_item_ids_since(vault.id, created.vault_revision)
        .await
        .unwrap();
    assert_eq!(deleted_since_create.len(), 1);
    assert_eq!(deleted_since_create[0].item_id, created.item_id);

    let active_revisions = storage
        .list_item_revisions_since(vault.id, 0)
        .await
        .unwrap();
    assert!(active_revisions.is_empty());

    let update_after_delete = storage
        .create_item_revision(CreateItemRevision {
            revision_id: None,
            item_id: created.item_id,
            vault_id: vault.id,
            expected_revision: created.revision,
            author_user_id: Some(owner.id),
            envelope: serde_json::json!({"ciphertext": "v2"}),
        })
        .await;
    assert!(matches!(update_after_delete, Err(StorageError::NotFound)));

    let stale_delete = storage
        .delete_item(DeleteItem {
            item_id: created.item_id,
            vault_id: vault.id,
            expected_revision: created.revision,
            author_user_id: Some(owner.id),
        })
        .await;
    assert!(matches!(stale_delete, Err(StorageError::NotFound)));
}

async fn vault_invite_lifecycle_on<S: StorageBackend + ?Sized>(storage: &S) {
    let owner = create_test_user_on(storage, "invite-owner@example.com").await;
    let recipient = create_test_user_on(storage, "invite-recipient@example.com").await;
    let recipient_device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: recipient.id,
            name: "invite recipient device".to_owned(),
            public_key: Some("invite-recipient-signing-key".to_owned()),
            encryption_public_key: Some("invite-recipient-encryption-key".to_owned()),
            fingerprint: "invite-recipient-device".to_owned(),
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
        })
        .await
        .unwrap();
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Invite Vault".to_owned(),
            kind: VaultKind::Shared,
            created_by: Some(owner.id),
            crypto_policy: serde_json::json!({"min_envelope_version": 1}),
        })
        .await
        .unwrap();
    storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id: owner.id,
            role: VaultRole::Owner,
            state: MemberState::Active,
        })
        .await
        .unwrap();

    let invite = storage
        .create_vault_invite(CreateVaultInvite {
            id: None,
            vault_id: vault.id,
            org_id: None,
            email: "INVITE-RECIPIENT@example.com".to_owned(),
            role: VaultRole::Editor,
            invited_by: Some(owner.id),
            vault_key_wrapping: serde_json::json!({
                "version": 3,
                "device_wrappings": [{
                    "device_id": recipient_device.id.to_string(),
                    "wrapping_type": "device_public_key",
                    "key_generation": 1,
                    "envelope": {"wrapped": "vault-key"}
                }]
            }),
            expires_at: None,
        })
        .await
        .unwrap();

    assert_eq!(invite.vault_id, vault.id);
    assert_eq!(invite.email, "invite-recipient@example.com");
    assert_eq!(invite.role, VaultRole::Editor);
    assert_eq!(invite.state, "pending");

    let pending = storage
        .list_pending_vault_invites_for_email("invite-recipient@example.com")
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, invite.id);
    assert_eq!(pending[0].vault_name, "Invite Vault");

    let member = storage
        .accept_vault_invite(AcceptVaultInvite {
            invite_id: invite.id,
            user_id: recipient.id,
            device_id: Some(recipient_device.id),
        })
        .await
        .unwrap();
    assert_eq!(member.vault_id, vault.id);
    assert_eq!(member.user_id, recipient.id);
    assert_eq!(member.role, VaultRole::Editor);
    assert_eq!(member.state, MemberState::Active);

    let wrappings = storage
        .list_key_wrappings_for_user_vault(recipient.id, vault.id)
        .await
        .unwrap();
    assert_eq!(wrappings.len(), 1);
    assert_eq!(
        wrappings[0].envelope,
        serde_json::json!({"wrapped": "vault-key"})
    );
    assert_eq!(wrappings[0].device_id, Some(recipient_device.id));
    assert_eq!(wrappings[0].wrapping_type, "device_public_key");

    let pending_after_accept = storage
        .list_pending_vault_invites_for_email("invite-recipient@example.com")
        .await
        .unwrap();
    assert!(pending_after_accept.is_empty());

    let second_accept = storage
        .accept_vault_invite(AcceptVaultInvite {
            invite_id: invite.id,
            user_id: recipient.id,
            device_id: Some(recipient_device.id),
        })
        .await;
    assert!(matches!(second_accept, Err(StorageError::NotFound)));

    let legacy_invite = storage
        .create_vault_invite(CreateVaultInvite {
            id: None,
            vault_id: vault.id,
            org_id: None,
            email: "invite-recipient@example.com".to_owned(),
            role: VaultRole::Editor,
            invited_by: Some(owner.id),
            vault_key_wrapping: serde_json::json!({"wrapped": "legacy-user-key"}),
            expires_at: None,
        })
        .await
        .unwrap();
    let legacy_accept = storage
        .accept_vault_invite(AcceptVaultInvite {
            invite_id: legacy_invite.id,
            user_id: recipient.id,
            device_id: Some(recipient_device.id),
        })
        .await;
    assert!(matches!(legacy_accept, Err(StorageError::NotFound)));
    assert!(
        storage
            .list_pending_vault_invites_for_email("invite-recipient@example.com")
            .await
            .unwrap()
            .iter()
            .any(|invite| invite.id == legacy_invite.id)
    );
}

async fn sync_checkpoint_persistence_on<S: StorageBackend + ?Sized>(storage: &S) {
    let user = create_test_user_on(storage, "checkpoint-owner@example.com").await;
    let vault = storage
        .create_vault(CreateVault {
            id: None,
            org_id: None,
            name: "Checkpoint Vault".to_owned(),
            kind: VaultKind::Personal,
            created_by: Some(user.id),
            crypto_policy: serde_json::json!({}),
        })
        .await
        .unwrap();
    let device = storage
        .create_device(CreateDevice {
            id: None,
            user_id: user.id,
            name: "checkpoint device".to_owned(),
            public_key: Some("checkpoint-device-public-key".to_owned()),
            encryption_public_key: None,
            fingerprint: "SHA256:checkpoint".to_owned(),
            state: DeviceState::Trusted,
            approval_code_hash: None,
            approval_expires_at: None,
            bootstrap_public_key: None,
        })
        .await
        .unwrap();

    let first_input = CreateSyncCheckpoint {
        vault_id: vault.id,
        vault_revision: 1,
        state_commitment: "state-commitment-1".to_owned(),
        checkpoint_hash: "checkpoint-hash-1".to_owned(),
        previous_checkpoint_hash: None,
        author_device_id: device.id,
        signature: "signature-1".to_owned(),
    };
    let first = storage
        .append_sync_checkpoint(first_input.clone())
        .await
        .unwrap();
    assert_eq!(first.vault_id, vault.id);
    assert_eq!(first.vault_revision, 1);
    assert_eq!(first.state_commitment, "state-commitment-1");
    assert_eq!(first.checkpoint_hash, "checkpoint-hash-1");
    assert_eq!(first.previous_checkpoint_hash, None);
    assert_eq!(first.author_device_id, device.id);
    assert_eq!(first.signature, "signature-1");

    let duplicate = storage.append_sync_checkpoint(first_input).await.unwrap();
    assert_eq!(duplicate.checkpoint_hash, first.checkpoint_hash);
    assert_eq!(duplicate.created_at, first.created_at);

    let competing = storage
        .append_sync_checkpoint(CreateSyncCheckpoint {
            vault_id: vault.id,
            vault_revision: 1,
            state_commitment: "state-commitment-conflict".to_owned(),
            checkpoint_hash: "checkpoint-hash-conflict".to_owned(),
            previous_checkpoint_hash: None,
            author_device_id: device.id,
            signature: "signature-conflict".to_owned(),
        })
        .await;
    assert!(matches!(
        competing,
        Err(StorageError::CheckpointConflict(CheckpointConflict {
            vault_id,
            vault_revision: 1,
            ref existing_checkpoint_hash,
            ref checkpoint_hash,
        })) if vault_id == vault.id
            && existing_checkpoint_hash == "checkpoint-hash-1"
            && checkpoint_hash == "checkpoint-hash-conflict"
    ));

    let second = storage
        .append_sync_checkpoint(CreateSyncCheckpoint {
            vault_id: vault.id,
            vault_revision: 2,
            state_commitment: "state-commitment-2".to_owned(),
            checkpoint_hash: "checkpoint-hash-2".to_owned(),
            previous_checkpoint_hash: Some(first.checkpoint_hash.clone()),
            author_device_id: device.id,
            signature: "signature-2".to_owned(),
        })
        .await
        .unwrap();

    let all = storage
        .list_sync_checkpoints_since(vault.id, 0)
        .await
        .unwrap();
    assert_eq!(
        all.iter()
            .map(|checkpoint| checkpoint.vault_revision)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(all[1].checkpoint_hash, second.checkpoint_hash);

    let after_first = storage
        .list_sync_checkpoints_since(vault.id, 1)
        .await
        .unwrap();
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0].checkpoint_hash, second.checkpoint_hash);

    assert_eq!(
        storage
            .find_sync_checkpoint(vault.id, 1)
            .await
            .unwrap()
            .unwrap()
            .checkpoint_hash,
        first.checkpoint_hash
    );
    assert!(
        storage
            .find_sync_checkpoint(vault.id, 3)
            .await
            .unwrap()
            .is_none()
    );
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
