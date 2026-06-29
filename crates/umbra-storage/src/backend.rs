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
