use serde::{Deserialize, Serialize};
use umbra_core::{DeviceId, ItemId, ItemKind, RevisionId, UserId, VaultId, VaultKind, VaultRole};

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
