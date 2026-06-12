use crate::convert::{
    item_kind_to_str, member_state_to_str, str_to_member_state, str_to_vault_kind,
    str_to_vault_role, vault_kind_to_str, vault_role_to_str,
};
use crate::*;
use serial_test::serial;
use umbra_core::{ItemKind, MemberState, OrgRole, VaultKind, VaultRole};

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
    assert_eq!(item_kind_to_str(&ItemKind::ApiKey), "api_key");
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
          AND table_name IN ('users', 'orgs', 'vaults', 'vault_members', 'vault_key_wrappings', 'item_revisions', 'sessions')
        "#,
    )
    .fetch_one(storage.pool())
    .await
    .unwrap();

    assert_eq!(tables, 7);
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
    storage
        .upsert_vault_member(UpsertVaultMember {
            vault_id: vault.id,
            user_id: owner.id,
            role: VaultRole::Owner,
            state: MemberState::Active,
        })
        .await
        .unwrap();
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
}

async fn fresh_test_storage() -> Option<Storage> {
    let Ok(database_url) = std::env::var("UMBRA_TEST_DATABASE_URL") else {
        eprintln!("skipping postgres test: UMBRA_TEST_DATABASE_URL is not set");
        return None;
    };
    let storage = Storage::connect(&database_url).await.unwrap();

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
