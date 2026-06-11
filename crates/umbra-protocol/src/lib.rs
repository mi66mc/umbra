use serde::{Deserialize, Serialize};
use umbra_core::{
    DeviceId, ItemId, ItemKind, OrgId, OrgRole, RevisionId, UserId, VaultId, VaultKind, VaultRole,
};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub protocol_version: u16,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: serde_json::Value,
    pub initial_device: DeviceRegisterRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRegisterStartRequest {
    pub protocol_version: u16,
    pub email: String,
    pub registration_request: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRegisterStartResponse {
    pub registration_id: uuid::Uuid,
    pub registration_response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRegisterFinishRequest {
    pub protocol_version: u16,
    pub registration_id: uuid::Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: serde_json::Value,
    pub initial_device: DeviceRegisterRequest,
    pub registration_upload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginStartRequest {
    pub protocol_version: u16,
    pub email: String,
    pub credential_request: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginStartResponse {
    pub login_id: uuid::Uuid,
    pub credential_response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishRequest {
    pub protocol_version: u16,
    pub login_id: uuid::Uuid,
    pub credential_finalization: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLoginFinishResponse {
    pub user_id: UserId,
    pub session_token: String,
    pub encrypted_private_key: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: UserId,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub protocol_version: u16,
    pub email: String,
    pub device_id: Option<DeviceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user_id: UserId,
    pub encrypted_private_key: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegisterRequest {
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustRequest {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub trust_proof: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    pub protocol_version: u16,
    pub name: String,
    pub kind: VaultKind,
    pub initial_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    pub protocol_version: u16,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgResponse {
    pub org_id: OrgId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddOrgMemberRequest {
    pub protocol_version: u16,
    pub user_id: UserId,
    pub role: OrgRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgVaultRequest {
    pub protocol_version: u16,
    pub name: String,
    pub kind: VaultKind,
    pub initial_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultResponse {
    pub vault_id: VaultId,
    pub org_id: Option<OrgId>,
    pub name: String,
    pub kind: VaultKind,
    pub current_key_generation: i64,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddVaultMemberRequest {
    pub protocol_version: u16,
    pub user_id: UserId,
    pub role: VaultRole,
    pub vault_key_wrapping: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationStatusResponse {
    pub vault_id: VaultId,
    pub current_key_generation: i64,
    pub needs_key_rotation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateVaultKeyRequest {
    pub protocol_version: u16,
    pub from_generation: i64,
    pub to_generation: i64,
    pub new_wrappings: Vec<RotationVaultKeyWrapping>,
    pub reencrypted_revisions: Vec<RotationItemRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationVaultKeyWrapping {
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub wrapping_type: String,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationItemRevision {
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub email: String,
    pub role: VaultRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub protocol_version: u16,
    pub invite_id: uuid::Uuid,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateItemRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub kind: ItemKind,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateItemRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteItemRequest {
    pub protocol_version: u16,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub expected_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRequest {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub vaults: Vec<VaultSyncCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSyncCursor {
    pub vault_id: VaultId,
    pub since_vault_revision: RevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    pub protocol_version: u16,
    pub vaults: Vec<VaultSyncChanges>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSyncChanges {
    pub vault_id: VaultId,
    pub latest_vault_revision: RevisionId,
    pub items: Vec<serde_json::Value>,
    pub deleted_items: Vec<ItemId>,
    pub key_wrappings: Vec<serde_json::Value>,
}
