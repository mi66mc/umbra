use chrono::{DateTime, Utc};
use serde_json::Value;
use umbra_core::{
    DeviceId, ItemId, ItemKind, MemberState, OrgId, OrgRole, RevisionId, UserId, VaultId,
    VaultKind, VaultRole,
};
use uuid::Uuid;

pub struct CreateUser {
    pub id: Option<UserId>,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: Value,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UpsertUserAuth {
    pub user_id: UserId,
    pub auth_method: String,
    pub auth_data: Value,
}

#[derive(Debug, Clone)]
pub struct UserAuthRecord {
    pub user_id: UserId,
    pub auth_method: String,
    pub auth_data: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateDevice {
    pub id: Option<DeviceId>,
    pub user_id: UserId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub trusted: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub public_key: Option<String>,
    pub fingerprint: String,
    pub trusted: bool,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreateVault {
    pub id: Option<VaultId>,
    pub org_id: Option<OrgId>,
    pub name: String,
    pub kind: VaultKind,
    pub created_by: Option<UserId>,
    pub crypto_policy: Value,
}

#[derive(Debug, Clone)]
pub struct VaultRecord {
    pub id: VaultId,
    pub org_id: Option<OrgId>,
    pub name: String,
    pub kind: VaultKind,
    pub vault_revision: RevisionId,
    pub current_key_generation: RevisionId,
    pub needs_key_rotation: bool,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub crypto_policy: Value,
}

#[derive(Debug, Clone)]
pub struct CreateOrg {
    pub id: Option<OrgId>,
    pub name: String,
    pub created_by: Option<UserId>,
}

#[derive(Debug, Clone)]
pub struct OrgRecord {
    pub id: OrgId,
    pub name: String,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UpsertOrgMember {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: OrgRole,
    pub state: MemberState,
}

#[derive(Debug, Clone)]
pub struct OrgMemberRecord {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: OrgRole,
    pub state: MemberState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct UpsertVaultMember {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
}

#[derive(Debug, Clone)]
pub struct VaultMemberRecord {
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub role: VaultRole,
    pub state: MemberState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateVaultKeyWrapping {
    pub id: Option<Uuid>,
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: Value,
    pub key_generation: RevisionId,
}

#[derive(Debug, Clone)]
pub struct VaultKeyWrappingRecord {
    pub id: Uuid,
    pub vault_id: VaultId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: Value,
    pub key_generation: RevisionId,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreateEncryptedItem {
    pub item_id: Option<ItemId>,
    pub revision_id: Option<Uuid>,
    pub vault_id: VaultId,
    pub kind: ItemKind,
    pub author_user_id: Option<UserId>,
    pub envelope: Value,
}

#[derive(Debug, Clone)]
pub struct CreateItemRevision {
    pub revision_id: Option<Uuid>,
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub expected_revision: RevisionId,
    pub author_user_id: Option<UserId>,
    pub envelope: Value,
}

#[derive(Debug, Clone)]
pub struct ItemRevisionRecord {
    pub id: Uuid,
    pub item_id: ItemId,
    pub vault_id: VaultId,
    pub revision: RevisionId,
    pub vault_revision: RevisionId,
    pub key_generation: RevisionId,
    pub author_user_id: Option<UserId>,
    pub envelope: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RotationStatusRecord {
    pub vault_id: VaultId,
    pub current_key_generation: RevisionId,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone)]
pub struct FinishVaultKeyRotation {
    pub vault_id: VaultId,
    pub author_user_id: Option<UserId>,
    pub from_generation: RevisionId,
    pub to_generation: RevisionId,
    pub new_wrappings: Vec<CreateVaultKeyWrapping>,
    pub reencrypted_revisions: Vec<RotationItemRevisionInput>,
}

#[derive(Debug, Clone)]
pub struct RotationItemRevisionInput {
    pub revision_id: Option<Uuid>,
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
    pub envelope: Value,
}

#[derive(Debug, Clone)]
pub struct AppendAuditLog {
    pub id: Option<Uuid>,
    pub actor_user_id: Option<UserId>,
    pub vault_id: Option<VaultId>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct AuditLogRecord {
    pub id: Uuid,
    pub actor_user_id: Option<UserId>,
    pub vault_id: Option<VaultId>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateSession {
    pub id: Option<Uuid>,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
