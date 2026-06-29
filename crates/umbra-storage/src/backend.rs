use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    AppendAuditLog, ApprovePendingDevice, AuditLogRecord, CreateDevice, CreateEncryptedItem,
    CreateItemRevision, CreateOrg, CreateRecoveryChallenge, CreateSession, CreateUser, CreateVault,
    CreateVaultKeyWrapping, DeviceRecord, FinishVaultKeyRotation, ItemRevisionRecord,
    OrgMemberRecord, OrgRecord, PostgresStorage, RecoveryChallengeRecord, RotationStatusRecord,
    SessionRecord, StorageError, UpsertOrgMember, UpsertUserAuth, UpsertVaultMember,
    UserAuthRecord, UserRecord, VaultKeyWrappingRecord, VaultMemberRecord, VaultRecord,
    VaultSyncStatusRecord,
};
use umbra_core::{DeviceId, OrgId, UserId, VaultId};

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError>;
    async fn find_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError>;
    async fn find_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError>;
    async fn upsert_user_auth(&self, input: UpsertUserAuth)
    -> Result<UserAuthRecord, StorageError>;
    async fn find_user_auth(&self, user_id: UserId) -> Result<UserAuthRecord, StorageError>;

    async fn create_device(&self, input: CreateDevice) -> Result<DeviceRecord, StorageError>;
    async fn list_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError>;
    async fn find_device_by_id(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError>;
    async fn list_pending_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError>;
    async fn find_pending_device_by_approval_hash(
        &self,
        user_id: UserId,
        approval_code_hash: &str,
    ) -> Result<DeviceRecord, StorageError>;
    async fn approve_pending_device(
        &self,
        input: ApprovePendingDevice,
    ) -> Result<DeviceRecord, StorageError>;
    async fn mark_device_trusted(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError>;
    async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError>;
    async fn create_recovery_challenge(
        &self,
        input: CreateRecoveryChallenge,
    ) -> Result<RecoveryChallengeRecord, StorageError>;
    async fn consume_recovery_challenge(
        &self,
        challenge_id: Uuid,
        user_id: UserId,
        device_id: DeviceId,
        challenge_hash: &str,
    ) -> Result<RecoveryChallengeRecord, StorageError>;

    async fn create_session(&self, input: CreateSession) -> Result<SessionRecord, StorageError>;
    async fn find_active_session_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<SessionRecord, StorageError>;
    async fn find_active_session_by_id(
        &self,
        session_id: Uuid,
    ) -> Result<SessionRecord, StorageError>;
    async fn remember_session_nonce(
        &self,
        session_id: Uuid,
        nonce: &str,
    ) -> Result<(), StorageError>;
    async fn revoke_sessions_for_device(&self, device_id: Uuid) -> Result<u64, StorageError>;

    async fn create_org(&self, input: CreateOrg) -> Result<OrgRecord, StorageError>;
    async fn find_org_by_id(&self, org_id: OrgId) -> Result<OrgRecord, StorageError>;
    async fn list_orgs_for_user(&self, user_id: UserId) -> Result<Vec<OrgRecord>, StorageError>;
    async fn upsert_org_member(
        &self,
        input: UpsertOrgMember,
    ) -> Result<OrgMemberRecord, StorageError>;
    async fn list_org_members(&self, org_id: OrgId) -> Result<Vec<OrgMemberRecord>, StorageError>;
    async fn find_org_member(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<OrgMemberRecord, StorageError>;

    async fn create_vault(&self, input: CreateVault) -> Result<VaultRecord, StorageError>;
    async fn find_vault_by_id(&self, vault_id: VaultId) -> Result<VaultRecord, StorageError>;
    async fn list_vaults_for_user(&self, user_id: UserId)
    -> Result<Vec<VaultRecord>, StorageError>;
    async fn upsert_vault_member(
        &self,
        input: UpsertVaultMember,
    ) -> Result<VaultMemberRecord, StorageError>;
    async fn list_vault_members(
        &self,
        vault_id: VaultId,
    ) -> Result<Vec<VaultMemberRecord>, StorageError>;
    async fn has_active_vault_membership(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<bool, StorageError>;
    async fn create_vault_key_wrapping(
        &self,
        input: CreateVaultKeyWrapping,
    ) -> Result<VaultKeyWrappingRecord, StorageError>;
    async fn list_key_wrappings_for_user_vault(
        &self,
        user_id: UserId,
        vault_id: VaultId,
    ) -> Result<Vec<VaultKeyWrappingRecord>, StorageError>;
    async fn remove_vault_member(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<(), StorageError>;
    async fn revoke_key_wrapping(&self, wrapping_id: Uuid) -> Result<(), StorageError>;
    async fn rotation_status(
        &self,
        vault_id: VaultId,
    ) -> Result<RotationStatusRecord, StorageError>;
    async fn vault_sync_status(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<VaultSyncStatusRecord, StorageError>;
    async fn finish_vault_key_rotation(
        &self,
        input: FinishVaultKeyRotation,
    ) -> Result<RotationStatusRecord, StorageError>;

    async fn create_item_revision(
        &self,
        input: CreateItemRevision,
    ) -> Result<ItemRevisionRecord, StorageError>;
    async fn create_encrypted_item(
        &self,
        input: CreateEncryptedItem,
    ) -> Result<ItemRevisionRecord, StorageError>;
    async fn list_item_revisions_since(
        &self,
        vault_id: VaultId,
        since_vault_revision: i64,
    ) -> Result<Vec<ItemRevisionRecord>, StorageError>;

    async fn append_audit_log(&self, input: AppendAuditLog)
    -> Result<AuditLogRecord, StorageError>;
}

#[async_trait]
impl StorageBackend for PostgresStorage {
    async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError> {
        PostgresStorage::create_user(self, input).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError> {
        PostgresStorage::find_user_by_email(self, email).await
    }

    async fn find_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError> {
        PostgresStorage::find_user_by_id(self, user_id).await
    }

    async fn upsert_user_auth(
        &self,
        input: UpsertUserAuth,
    ) -> Result<UserAuthRecord, StorageError> {
        PostgresStorage::upsert_user_auth(self, input).await
    }

    async fn find_user_auth(&self, user_id: UserId) -> Result<UserAuthRecord, StorageError> {
        PostgresStorage::find_user_auth(self, user_id).await
    }

    async fn create_device(&self, input: CreateDevice) -> Result<DeviceRecord, StorageError> {
        PostgresStorage::create_device(self, input).await
    }

    async fn list_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        PostgresStorage::list_devices_for_user(self, user_id).await
    }

    async fn find_device_by_id(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError> {
        PostgresStorage::find_device_by_id(self, device_id).await
    }

    async fn list_pending_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        PostgresStorage::list_pending_devices_for_user(self, user_id).await
    }

    async fn find_pending_device_by_approval_hash(
        &self,
        user_id: UserId,
        approval_code_hash: &str,
    ) -> Result<DeviceRecord, StorageError> {
        PostgresStorage::find_pending_device_by_approval_hash(self, user_id, approval_code_hash)
            .await
    }

    async fn approve_pending_device(
        &self,
        input: ApprovePendingDevice,
    ) -> Result<DeviceRecord, StorageError> {
        PostgresStorage::approve_pending_device(self, input).await
    }

    async fn mark_device_trusted(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError> {
        PostgresStorage::mark_device_trusted(self, device_id).await
    }

    async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError> {
        PostgresStorage::revoke_device(self, device_id).await
    }

    async fn create_recovery_challenge(
        &self,
        input: CreateRecoveryChallenge,
    ) -> Result<RecoveryChallengeRecord, StorageError> {
        PostgresStorage::create_recovery_challenge(self, input).await
    }

    async fn consume_recovery_challenge(
        &self,
        challenge_id: Uuid,
        user_id: UserId,
        device_id: DeviceId,
        challenge_hash: &str,
    ) -> Result<RecoveryChallengeRecord, StorageError> {
        PostgresStorage::consume_recovery_challenge(
            self,
            challenge_id,
            user_id,
            device_id,
            challenge_hash,
        )
        .await
    }

    async fn create_session(&self, input: CreateSession) -> Result<SessionRecord, StorageError> {
        PostgresStorage::create_session(self, input).await
    }

    async fn find_active_session_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<SessionRecord, StorageError> {
        PostgresStorage::find_active_session_by_hash(self, token_hash).await
    }

    async fn find_active_session_by_id(
        &self,
        session_id: Uuid,
    ) -> Result<SessionRecord, StorageError> {
        PostgresStorage::find_active_session_by_id(self, session_id).await
    }

    async fn remember_session_nonce(
        &self,
        session_id: Uuid,
        nonce: &str,
    ) -> Result<(), StorageError> {
        PostgresStorage::remember_session_nonce(self, session_id, nonce).await
    }

    async fn revoke_sessions_for_device(&self, device_id: Uuid) -> Result<u64, StorageError> {
        PostgresStorage::revoke_sessions_for_device(self, device_id).await
    }

    async fn create_org(&self, input: CreateOrg) -> Result<OrgRecord, StorageError> {
        PostgresStorage::create_org(self, input).await
    }

    async fn find_org_by_id(&self, org_id: OrgId) -> Result<OrgRecord, StorageError> {
        PostgresStorage::find_org_by_id(self, org_id).await
    }

    async fn list_orgs_for_user(&self, user_id: UserId) -> Result<Vec<OrgRecord>, StorageError> {
        PostgresStorage::list_orgs_for_user(self, user_id).await
    }

    async fn upsert_org_member(
        &self,
        input: UpsertOrgMember,
    ) -> Result<OrgMemberRecord, StorageError> {
        PostgresStorage::upsert_org_member(self, input).await
    }

    async fn list_org_members(&self, org_id: OrgId) -> Result<Vec<OrgMemberRecord>, StorageError> {
        PostgresStorage::list_org_members(self, org_id).await
    }

    async fn find_org_member(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<OrgMemberRecord, StorageError> {
        PostgresStorage::find_org_member(self, org_id, user_id).await
    }

    async fn create_vault(&self, input: CreateVault) -> Result<VaultRecord, StorageError> {
        PostgresStorage::create_vault(self, input).await
    }

    async fn find_vault_by_id(&self, vault_id: VaultId) -> Result<VaultRecord, StorageError> {
        PostgresStorage::find_vault_by_id(self, vault_id).await
    }

    async fn list_vaults_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<VaultRecord>, StorageError> {
        PostgresStorage::list_vaults_for_user(self, user_id).await
    }

    async fn upsert_vault_member(
        &self,
        input: UpsertVaultMember,
    ) -> Result<VaultMemberRecord, StorageError> {
        PostgresStorage::upsert_vault_member(self, input).await
    }

    async fn list_vault_members(
        &self,
        vault_id: VaultId,
    ) -> Result<Vec<VaultMemberRecord>, StorageError> {
        PostgresStorage::list_vault_members(self, vault_id).await
    }

    async fn has_active_vault_membership(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<bool, StorageError> {
        PostgresStorage::has_active_vault_membership(self, vault_id, user_id).await
    }

    async fn create_vault_key_wrapping(
        &self,
        input: CreateVaultKeyWrapping,
    ) -> Result<VaultKeyWrappingRecord, StorageError> {
        PostgresStorage::create_vault_key_wrapping(self, input).await
    }

    async fn list_key_wrappings_for_user_vault(
        &self,
        user_id: UserId,
        vault_id: VaultId,
    ) -> Result<Vec<VaultKeyWrappingRecord>, StorageError> {
        PostgresStorage::list_key_wrappings_for_user_vault(self, user_id, vault_id).await
    }

    async fn remove_vault_member(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<(), StorageError> {
        PostgresStorage::remove_vault_member(self, vault_id, user_id).await
    }

    async fn revoke_key_wrapping(&self, wrapping_id: Uuid) -> Result<(), StorageError> {
        PostgresStorage::revoke_key_wrapping(self, wrapping_id).await
    }

    async fn rotation_status(
        &self,
        vault_id: VaultId,
    ) -> Result<RotationStatusRecord, StorageError> {
        PostgresStorage::rotation_status(self, vault_id).await
    }

    async fn vault_sync_status(
        &self,
        vault_id: VaultId,
        user_id: UserId,
    ) -> Result<VaultSyncStatusRecord, StorageError> {
        PostgresStorage::vault_sync_status(self, vault_id, user_id).await
    }

    async fn finish_vault_key_rotation(
        &self,
        input: FinishVaultKeyRotation,
    ) -> Result<RotationStatusRecord, StorageError> {
        PostgresStorage::finish_vault_key_rotation(self, input).await
    }

    async fn create_item_revision(
        &self,
        input: CreateItemRevision,
    ) -> Result<ItemRevisionRecord, StorageError> {
        PostgresStorage::create_item_revision(self, input).await
    }

    async fn create_encrypted_item(
        &self,
        input: CreateEncryptedItem,
    ) -> Result<ItemRevisionRecord, StorageError> {
        PostgresStorage::create_encrypted_item(self, input).await
    }

    async fn list_item_revisions_since(
        &self,
        vault_id: VaultId,
        since_vault_revision: i64,
    ) -> Result<Vec<ItemRevisionRecord>, StorageError> {
        PostgresStorage::list_item_revisions_since(self, vault_id, since_vault_revision).await
    }

    async fn append_audit_log(
        &self,
        input: AppendAuditLog,
    ) -> Result<AuditLogRecord, StorageError> {
        PostgresStorage::append_audit_log(self, input).await
    }
}

#[async_trait]
impl StorageBackend for crate::sqlite::SqliteStorage {
    async fn create_user(&self, input: CreateUser) -> Result<UserRecord, StorageError> {
        crate::sqlite::SqliteStorage::create_user(self, input).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<UserRecord, StorageError> {
        crate::sqlite::SqliteStorage::find_user_by_email(self, email).await
    }

    async fn find_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError> {
        crate::sqlite::SqliteStorage::find_user_by_id(self, user_id).await
    }

    async fn upsert_user_auth(
        &self,
        input: UpsertUserAuth,
    ) -> Result<UserAuthRecord, StorageError> {
        crate::sqlite::SqliteStorage::upsert_user_auth(self, input).await
    }

    async fn find_user_auth(&self, user_id: UserId) -> Result<UserAuthRecord, StorageError> {
        crate::sqlite::SqliteStorage::find_user_auth(self, user_id).await
    }

    async fn create_device(&self, input: CreateDevice) -> Result<DeviceRecord, StorageError> {
        crate::sqlite::SqliteStorage::create_device(self, input).await
    }

    async fn list_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        crate::sqlite::SqliteStorage::list_devices_for_user(self, user_id).await
    }

    async fn find_device_by_id(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError> {
        crate::sqlite::SqliteStorage::find_device_by_id(self, device_id).await
    }

    async fn list_pending_devices_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        crate::sqlite::SqliteStorage::list_pending_devices_for_user(self, user_id).await
    }

    async fn find_pending_device_by_approval_hash(
        &self,
        user_id: UserId,
        approval_code_hash: &str,
    ) -> Result<DeviceRecord, StorageError> {
        crate::sqlite::SqliteStorage::find_pending_device_by_approval_hash(
            self,
            user_id,
            approval_code_hash,
        )
        .await
    }

    async fn approve_pending_device(
        &self,
        input: ApprovePendingDevice,
    ) -> Result<DeviceRecord, StorageError> {
        crate::sqlite::SqliteStorage::approve_pending_device(self, input).await
    }

    async fn mark_device_trusted(&self, device_id: DeviceId) -> Result<DeviceRecord, StorageError> {
        crate::sqlite::SqliteStorage::mark_device_trusted(self, device_id).await
    }

    async fn revoke_device(&self, device_id: DeviceId) -> Result<(), StorageError> {
        crate::sqlite::SqliteStorage::revoke_device(self, device_id).await
    }

    async fn create_recovery_challenge(
        &self,
        input: CreateRecoveryChallenge,
    ) -> Result<RecoveryChallengeRecord, StorageError> {
        crate::sqlite::SqliteStorage::create_recovery_challenge(self, input).await
    }

    async fn consume_recovery_challenge(
        &self,
        challenge_id: Uuid,
        user_id: UserId,
        device_id: DeviceId,
        challenge_hash: &str,
    ) -> Result<RecoveryChallengeRecord, StorageError> {
        crate::sqlite::SqliteStorage::consume_recovery_challenge(
            self,
            challenge_id,
            user_id,
            device_id,
            challenge_hash,
        )
        .await
    }

    async fn create_session(&self, input: CreateSession) -> Result<SessionRecord, StorageError> {
        crate::sqlite::SqliteStorage::create_session(self, input).await
    }

    async fn find_active_session_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<SessionRecord, StorageError> {
        crate::sqlite::SqliteStorage::find_active_session_by_hash(self, token_hash).await
    }

    async fn find_active_session_by_id(
        &self,
        session_id: Uuid,
    ) -> Result<SessionRecord, StorageError> {
        crate::sqlite::SqliteStorage::find_active_session_by_id(self, session_id).await
    }

    async fn remember_session_nonce(
        &self,
        session_id: Uuid,
        nonce: &str,
    ) -> Result<(), StorageError> {
        crate::sqlite::SqliteStorage::remember_session_nonce(self, session_id, nonce).await
    }

    async fn revoke_sessions_for_device(&self, device_id: Uuid) -> Result<u64, StorageError> {
        crate::sqlite::SqliteStorage::revoke_sessions_for_device(self, device_id).await
    }

    async fn create_org(&self, _input: CreateOrg) -> Result<OrgRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite create_org",
        ))
    }

    async fn find_org_by_id(&self, _org_id: OrgId) -> Result<OrgRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite find_org_by_id",
        ))
    }

    async fn list_orgs_for_user(&self, _user_id: UserId) -> Result<Vec<OrgRecord>, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite list_orgs_for_user",
        ))
    }

    async fn upsert_org_member(
        &self,
        _input: UpsertOrgMember,
    ) -> Result<OrgMemberRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite upsert_org_member",
        ))
    }

    async fn list_org_members(&self, _org_id: OrgId) -> Result<Vec<OrgMemberRecord>, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite list_org_members",
        ))
    }

    async fn find_org_member(
        &self,
        _org_id: OrgId,
        _user_id: UserId,
    ) -> Result<OrgMemberRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite find_org_member",
        ))
    }

    async fn create_vault(&self, _input: CreateVault) -> Result<VaultRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite create_vault",
        ))
    }

    async fn find_vault_by_id(&self, _vault_id: VaultId) -> Result<VaultRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite find_vault_by_id",
        ))
    }

    async fn list_vaults_for_user(
        &self,
        _user_id: UserId,
    ) -> Result<Vec<VaultRecord>, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite list_vaults_for_user",
        ))
    }

    async fn upsert_vault_member(
        &self,
        _input: UpsertVaultMember,
    ) -> Result<VaultMemberRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite upsert_vault_member",
        ))
    }

    async fn list_vault_members(
        &self,
        _vault_id: VaultId,
    ) -> Result<Vec<VaultMemberRecord>, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite list_vault_members",
        ))
    }

    async fn has_active_vault_membership(
        &self,
        _vault_id: VaultId,
        _user_id: UserId,
    ) -> Result<bool, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite has_active_vault_membership",
        ))
    }

    async fn create_vault_key_wrapping(
        &self,
        _input: CreateVaultKeyWrapping,
    ) -> Result<VaultKeyWrappingRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite create_vault_key_wrapping",
        ))
    }

    async fn list_key_wrappings_for_user_vault(
        &self,
        _user_id: UserId,
        _vault_id: VaultId,
    ) -> Result<Vec<VaultKeyWrappingRecord>, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite list_key_wrappings_for_user_vault",
        ))
    }

    async fn remove_vault_member(
        &self,
        _vault_id: VaultId,
        _user_id: UserId,
    ) -> Result<(), StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite remove_vault_member",
        ))
    }

    async fn revoke_key_wrapping(&self, _wrapping_id: Uuid) -> Result<(), StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite revoke_key_wrapping",
        ))
    }

    async fn rotation_status(
        &self,
        _vault_id: VaultId,
    ) -> Result<RotationStatusRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite rotation_status",
        ))
    }

    async fn vault_sync_status(
        &self,
        _vault_id: VaultId,
        _user_id: UserId,
    ) -> Result<VaultSyncStatusRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite vault_sync_status",
        ))
    }

    async fn finish_vault_key_rotation(
        &self,
        _input: FinishVaultKeyRotation,
    ) -> Result<RotationStatusRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite finish_vault_key_rotation",
        ))
    }

    async fn create_item_revision(
        &self,
        _input: CreateItemRevision,
    ) -> Result<ItemRevisionRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite create_item_revision",
        ))
    }

    async fn create_encrypted_item(
        &self,
        _input: CreateEncryptedItem,
    ) -> Result<ItemRevisionRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite create_encrypted_item",
        ))
    }

    async fn list_item_revisions_since(
        &self,
        _vault_id: VaultId,
        _since_vault_revision: i64,
    ) -> Result<Vec<ItemRevisionRecord>, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite list_item_revisions_since",
        ))
    }

    async fn append_audit_log(
        &self,
        _input: AppendAuditLog,
    ) -> Result<AuditLogRecord, StorageError> {
        Err(StorageError::UnsupportedBackendOperation(
            "sqlite append_audit_log",
        ))
    }
}
